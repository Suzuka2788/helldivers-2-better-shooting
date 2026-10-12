-- HD2-Addon: mods/suzuka/semi_hold
local GAME_SHA="2e2c3b7c2500646dadd5f2b4c6e0504dbb7e7896139f64cddc0d1813c718f51e"
local EXE_SHA="f5fee03dcfdb2e553a4752c283590950ac13316b376d8196aa556ff0400d5f06"
local create_memory=(function()
-- Read-only Windows adapter. preview8: reads use ReadProcessMemory only.
-- VirtualQuery cost grows with the resident run after the queried address
-- (Flag Pelican 0.5.12 live log: 98% of read time, ~0.136 ms per call), and
-- ReadProcessMemory fails whole on guard, no-access, reserved and freed pages
-- without clearing PAGE_GUARD. No writer is included.
return function()
    local ffi=require('ffi')
    assert(ffi.os=='Windows' and ffi.abi('64bit'),'windows_x64_required')
    ffi.cdef[[
        void *GetModuleHandleA(const char *);
        uint32_t GetModuleFileNameW(void *,uint16_t *,uint32_t);
        void *GetCurrentProcess(void);
        int ReadProcessMemory(void *,const void *,void *,size_t,size_t *);
        void *CreateFileW(const uint16_t *,uint32_t,uint32_t,void *,uint32_t,uint32_t,void *);
        int ReadFile(void *,void *,uint32_t,uint32_t *,void *);
        int CloseHandle(void *);
        int32_t BCryptOpenAlgorithmProvider(void **,const uint16_t *,const uint16_t *,uint32_t);
        int32_t BCryptCreateHash(void *,void **,void *,uint32_t,const void *,uint32_t,uint32_t);
        int32_t BCryptHashData(void *,const void *,uint32_t,uint32_t);
        int32_t BCryptFinishHash(void *,void *,uint32_t,uint32_t);
        int32_t BCryptDestroyHash(void *);
        int32_t BCryptCloseAlgorithmProvider(void *,uint32_t);
    ]]
    local k,b=ffi.load('kernel32'),ffi.load('bcrypt')
    local process=k.GetCurrentProcess()
    local read_out=ffi.new('uint8_t[4096]')
    local read_count=ffi.new('size_t[1]')
    local pointer_buffer=ffi.new('uint64_t[1]')
    local api={stats={reads=0,failed=0}}
    local stats=api.stats
    function api.module(name)
        local p=k.GetModuleHandleA(name)
        if p==nil or p==ffi.NULL then return nil end
        return tonumber(ffi.cast('uintptr_t',p))
    end
    function api.pointer(bytes)
        if not bytes or #bytes~=8 then return nil end
        ffi.copy(pointer_buffer,bytes,8)
        local value=pointer_buffer[0]
        if value<65536 or value>=0x800000000000 then return nil end
        return tonumber(value)
    end
    function api.read(address,size)
        if type(address)~='number' or type(size)~='number' or size<=0 or size>4096
            or address<65536 or address+size>=0x800000000000 then return nil end
        stats.reads=stats.reads+1
        if k.ReadProcessMemory(process,ffi.cast('const void *',address),read_out,size,read_count)==0
            or tonumber(read_count[0])~=size then
            stats.failed=stats.failed+1
            return nil
        end
        return ffi.string(read_out,size)
    end
    function api.module_hash(address)
        local cache=rawget(_G,'SuzukaShootingModuleHashes')
        if not cache then
            cache={values={},hits=0,misses=0}
            rawset(_G,'SuzukaShootingModuleHashes',cache)
        end
        local verified=cache.values[address]
        if verified then cache.hits=cache.hits+1;return verified end
        cache.misses=cache.misses+1
        local cached=rawget(_G,'TongzVerifiedGameDllHash')
        if type(cached)=='table' and cached.address==address
            and type(cached.sha256)=='string' and #cached.sha256==64 then
            cache.values[address]=cached.sha256;return cached.sha256
        end
        local path=ffi.new('uint16_t[32768]')
        local n=k.GetModuleFileNameW(ffi.cast('void *',address),path,32768)
        assert(n>0 and n<32768,'game_dll_path_unavailable')
        local file=k.CreateFileW(path,0x80000000,7,nil,3,0x08000000,nil)
        assert(file~=ffi.cast('void *',-1),'game_dll_file_unavailable')
        local algorithm,hash=ffi.new('void *[1]'),ffi.new('void *[1]')
        local ok,result=pcall(function()
            local name=ffi.new('uint16_t[7]',{83,72,65,50,53,54,0})
            assert(b.BCryptOpenAlgorithmProvider(algorithm,name,nil,0)==0,'sha256_provider')
            assert(b.BCryptCreateHash(algorithm[0],hash,nil,0,nil,0,0)==0,'sha256_create')
            local chunk,count=ffi.new('uint8_t[65536]'),ffi.new('uint32_t[1]')
            local total=0
            while true do
                assert(k.ReadFile(file,chunk,65536,count,nil)~=0,'game_dll_read')
                if count[0]==0 then break end
                total=total+tonumber(count[0])
                assert(total<=64*1024*1024,'game_dll_too_large')
                assert(b.BCryptHashData(hash[0],chunk,count[0],0)==0,'sha256_update')
            end
            local digest,parts=ffi.new('uint8_t[32]'),{}
            assert(b.BCryptFinishHash(hash[0],digest,32,0)==0,'sha256_finish')
            for i=0,31 do parts[#parts+1]=string.format('%02x',digest[i]) end
            return table.concat(parts)
        end)
        if hash[0]~=nil then b.BCryptDestroyHash(hash[0]) end
        if algorithm[0]~=nil then b.BCryptCloseAlgorithmProvider(algorithm[0],0) end
        k.CloseHandle(file)
        assert(ok,result)
        rawset(_G,'TongzVerifiedGameDllHash',{address=address,sha256=result})
        cache.values[address]=result
        return result
    end
    return api
end

end)()
local policy=(function()
local M={}
function M.new(api,options)
    options=options or {rate_factor=1,semi_enabled=true}
    local s={status='IDLE',requests=0,resets=0,blocked=false}
    local function same(a,b)
        return a.key==b.key and a.weapon==b.weapon and a.manager==b.manager
            and a.slot==b.slot and a.mode==b.mode
    end
    function s:shutdown()self.armed=nil;self.blocked=true end
    function s:step()
        if not api.down() then
            self.armed=nil;self.blocked=false;self.stage=nil;self.status='RELEASED';return
        end
        if options.semi_enabled==false or options.rate_factor<=0 then
            self.armed=nil;self.stage=nil;self.blocked=true
            self.status='SEMI_REPEAT_DISABLED';return
        end
        -- Guarded: false as soon as the hold cannot qualify (treated like nil).
        local c=api.snapshot(true);self.observed=c
        if not c or not c.input_held or c.mode~=2 or c.has_charge then
            if self.armed then self.blocked=true;self.armed=nil end
            self.status='GUARD_IDLE';return
        end
        if self.blocked then self.status='RELEASE_TO_REARM';return end
        if self.armed and not same(c,self.armed) then
            self.armed=nil;self.blocked=true;self.status='WEAPON_CHANGED_RELEASE_TO_REARM';return
        end
        local now=api.now()
        if not self.armed then
            if c.phase==4 and c.active then
                self.armed=c;self.stage='shot';self.shot_time=nil;self.interval=nil
                self.deadline=now+10
            end
            self.status='WAITING_NATIVE_SHOT';return
        end
        if now>self.deadline then self:shutdown();self.status='STALLED_RELEASE_TO_REARM';return end
        if self.stage=='reset' then
            if c.phase~=0 or c.active or c.shots~=0 or c.cooldown>0 then
                self.status='WAITING_NATIVE_RESET';return
            end
            if self.shot_time and now<self.shot_time+self.interval/options.rate_factor then
                self.status='RATE_LIMIT_WAIT';return
            end
            api.start(c);self.requests=self.requests+1;self.stage='pending'
            self.deadline=now+10;self.status='REQUESTED_NEXT_SHOT';return
        end
        if self.stage=='pending' then
            if c.phase~=4 or not c.active then self.status='WAITING_NATIVE_TRIGGER';return end
            self.stage='shot'
        end
        if c.shots>=1 then
            if c.interval then
                self.interval=c.interval
                self.shot_time=now-math.max(0,c.interval-math.max(c.cooldown,0))
            end
            api.stop(c);self.resets=self.resets+1;self.stage='reset'
            self.deadline=now+math.max(10,(c.interval or 0)/options.rate_factor+2)
            self.status='RELEASE_COMPLETED_SHOT';return
        end
        self.status='WAITING_NATIVE_SHOT'
    end
    return s
end
return M

end)()
local create_menu=(function()
return function(state)
    local id='suzuka_better_shooting.semi_rate_factor'
    local enabled_id='suzuka_better_shooting.semi_enabled'
    local menu
    -- Older menus without set() still reset the live factor; only the saved row stays.
    local function reset_factor()
        state.rate_factor=1
        if type(menu.set)=='function' then menu.set(id,1) end
    end
    local function apply_enabled(value)
        if type(value)~='boolean' then return end
        state.semi_enabled=value
        if not value then reset_factor() end
    end
    local function apply(value)
        if not state.semi_enabled then reset_factor();return end
        if type(value)=='number' and value==value and value>=0 and value<=1 then
            state.rate_factor=math.floor(value*20+0.5)/20
        end
    end
    -- Registers once. A missing menu is retried each frame (one global read); an
    -- incompatible menu or a refused row stops retrying and keeps the defaults.
    return function()
        if state.menu~='WAITING' then return end
        menu=rawget(_G,'ModOptionsMenu')
        if not menu then return end
        if type(menu)~='table' or menu.api~=1 or type(menu.register_option)~='function'
            or type(menu.get)~='function' or type(menu.on_change)~='function' then
            state.menu='INCOMPATIBLE_DEFAULTS';return
        end
        local ok,reason=menu.register_option(enabled_id,{
            type='toggle',mod='Suzuka Better Shooting',mod_id='suzuka.shooting_experience_optimization',
            label='SEMI-AUTO HOLD TO FIRE',default=true,
            description='Enable held-fire repeat for eligible non-charged semi-auto weapons. OFF restores manual single fire and resets rate factor to 1. Apply to save; release Fire before re-enabling.'})
        if not ok then state.menu='REGISTER_FAILED';state.menu_error=reason;return end
        ok,reason=menu.register_option(id,{
            type='slider',mod='Suzuka Better Shooting',mod_id='suzuka.shooting_experience_optimization',
            label='SEMI-AUTO MAX RATE FACTOR',min=0,max=1,step=.05,decimals=2,default=1,
            description='Maximum RPM = native RPM x factor. 0 disables held semi-auto repeat; 0.5 requests half rate; 1 uses native rate. Native cooldown still applies. Apply to save.'})
        if not ok then state.menu='REGISTER_FAILED';state.menu_error=reason;return end
        apply_enabled(menu.get(enabled_id));apply(menu.get(id))
        menu.on_change(enabled_id,apply_enabled);menu.on_change(id,apply)
        state.menu='REGISTERED'
    end
end

end)()
local create_runtime=(function()
-- Known-build native adapter for held single fire, derived from Burst Hold v1.0.0
-- runtime.lua (shared helpers kept byte-identical, see test_offline.py).
-- No weapon-stat or executable-page writes.
return function(memory,game,signatures)
    local ffi,bit=require('ffi'),require('bit')
    ffi.cdef[[short GetAsyncKeyState(int); void *GetForegroundWindow(void);
        uint32_t GetWindowThreadProcessId(void *,uint32_t *);
        uint32_t GetCurrentProcessId(void);]]
    pcall(ffi.cdef,'int QueryPerformanceCounter(int64_t *); int QueryPerformanceFrequency(int64_t *);')
    local user,kernel=ffi.load('user32'),ffi.load('kernel32')
    local pid=ffi.new('uint32_t[1]')
    local own_pid=kernel.GetCurrentProcessId()
    local function focused()
        local window=user.GetForegroundWindow()
        if window==nil then return false end
        user.GetWindowThreadProcessId(window,pid)
        return pid[0]==own_pid
    end
    local f=ffi.new('float[1]')
    local slot_offsets={[1]=0,[2]=4,[3]=8,[6]=12}
    local function u32(s,o)
        if not s or #s<o+4 then return nil end
        local a,b,c,d=s:byte(o+1,o+4)
        return a+b*256+c*65536+d*16777216
    end
    local function ptr(a)return memory.pointer(memory.read(a,8))end
    local function lookup(address,key,limit)
        local h=memory.read(address,20)
        if not h then return nil end
        local rows,capacity,empty,mult=memory.pointer(h:sub(1,8)),u32(h,8),u32(h,12),u32(h,16)
        if not rows or capacity==0 or capacity>limit or bit.band(capacity,capacity-1)~=0
            or key==empty or key==0xffffffff then return nil end
        local product=tonumber(ffi.cast('uint32_t',ffi.new('uint64_t',key)*mult))
        for probe=0,math.min(capacity,128)-1 do
            local row=memory.read(rows+8*bit.band(product+probe,capacity-1),8)
            if not row then return nil end
            if u32(row,0)==key then
                local index=u32(row,4)
                return index~=0xffffffff and index or nil
            end
            if u32(row,0)==empty then return nil end
        end
    end
    local function component(global,map_off,entities_off,key,limit)
        local manager=ptr(game+global)
        local index=manager and lookup(manager+map_off,key,limit)
        local entities=index and ptr(manager+entities_off)
        local entity=entities and ptr(entities+index*8)
        local identity=entity and memory.read(entity,24)
        if not identity or u32(identity,8)~=key or bit.band(identity:byte(21),3)~=1 then return nil end
        return manager,index,entity,identity
    end
    for address,bytes in pairs(signatures) do
        assert(memory.read(game+address,#bytes)==bytes,'NATIVE_SIGNATURE_MISMATCH')
    end
    local request=ffi.cast('void (*)(void *,uint32_t,uint32_t)',game+0x786be0)
    local release=ffi.cast('void (*)(void *,uint32_t,uint32_t)',game+0x786df0)
    -- true/false only when the ChargeComponent map answers; nil when a read
    -- fails or the map is malformed, so a failed read never counts as no charge.
    local function has_charge(weapon)
        local cm=ptr(game+0x3326c20)
        local h=cm and memory.read(cm+0x20,20)
        if not h then return nil end
        local rows,capacity,empty,mult=memory.pointer(h:sub(1,8)),u32(h,8),u32(h,12),u32(h,16)
        if capacity==0 then return false end
        if not rows or capacity>8192 or bit.band(capacity,capacity-1)~=0 or weapon==empty then return nil end
        local product=tonumber(ffi.cast('uint32_t',ffi.new('uint64_t',weapon)*mult))
        for probe=0,math.min(capacity,128)-1 do
            local row=memory.read(rows+8*bit.band(product+probe,capacity-1),8)
            if not row then return nil end
            local key=u32(row,0)
            if key==weapon then return u32(row,4)~=0xffffffff end
            if key==empty then return false end
        end
        if capacity<=128 then return false end
    end
    local api={}
    -- QPC seconds; GetTickCount64 moved in ~15.6 ms steps.
    local counter=ffi.new('int64_t[1]')
    kernel.QueryPerformanceFrequency(counter)
    local seconds_per_count=1/tonumber(counter[0])
    function api.now()kernel.QueryPerformanceCounter(counter);return tonumber(counter[0])*seconds_per_count end
    -- Button first: an idle mouse skips the two window calls.
    function api.down()
        return bit.band(tonumber(user.GetAsyncKeyState(1)),0x8000)~=0 and focused()
    end
    -- guard=true returns false as soon as the hold cannot qualify (input not
    -- held, fire mode not Single, ChargeComponent present), skipping the
    -- Trigger and ProjectileWeapon lookups. The weapon-settings call is not
    -- needed for single fire and is never made.
    function api.snapshot(guard)
        local owner,pm=ptr(game+0x3326b90),ptr(game+0x3326468)
        if not owner or not pm then return nil end
        local net=u32(memory.read(pm+0x3a8,4),0)
        if not net or net==0 or net==0x7fff or net==0xffffffff then return nil end
        local ei=lookup(owner+0xf21a88,net,1048576)
        if not ei or ei>=262144 then return nil end
        local avatar=memory.read(owner+0xf31ad8+ei*24,24)
        if not avatar or avatar:sub(1,8)~='\151\250\77\41\77\51\28\77'
            or u32(avatar,16)~=net or bit.band(avatar:byte(21),3)~=1 then return nil end
        local id=u32(avatar,8)
        local am=ptr(game+0x3326d20)
        local ai=am and lookup(am+0xf8,id,64)
        -- AvatarManager embeds its entity-pointer slots at +0x110.
        local ae=ai and ptr(am+0x110+ai*8)
        local aid=ae and memory.read(ae,24)
        if not am or not ai or ai>=8 or aid~=avatar then return nil end
        local fire=memory.read(am+0x150+ai*0xa7aec+0x1b68+9*32,32)
        if not fire then return nil end
        ffi.copy(f,fire:sub(9,12),4)
        local held=tonumber(f[0])
        local input_held=fire:byte(1)~=0 and held>0 and held<86400
        if guard and not input_held then return false end
        local wm,wi,_,wid=component(0x3326420,0x30,0x48,id,8192)
        if not wm or wi>=4096 or wid~=avatar then return nil end
        local slots=ptr(wm+0x60);local requests=ptr(wm+0x58);local phases=ptr(wm+0x68)
        if not slots or not requests or not phases then return nil end
        local weapon=u32(memory.read(slots+wi*0x1d0,4),0)
        if not weapon or weapon==0 or weapon==0xffffffff then return nil end
        -- Equipment confirms slot zero is the actually selected handheld gun.
        local im,ii=component(0x3326738,0x28,0x40,id,4096)
        local inventory=im and ptr(im+0x50)
        local inv=inventory and memory.read(inventory+ii*48,48)
        if not inv then return nil end
        local active=u32(inv,28)
        local offset=slot_offsets[active]
        if not offset or u32(inv,offset)~=weapon then return nil end
        local dm,di,_,identity=component(0x3326ce0,0x30,0x48,weapon,32768)
        if not dm or di>=8192 then return nil end
        local modes=ptr(dm+0x60)
        local mode=modes and u32(memory.read(modes+di*12,4),0)
        if not mode or mode>8 then return nil end
        if guard and mode~=2 then return false end
        local charge=has_charge(weapon)
        if charge==nil then return nil end
        if guard and charge then return false end
        local tm,ti,_,tid=component(0x3326660,0x28,0x40,weapon,8192)
        if not tm or ti>=4096 or tid~=identity then return nil end
        local flags=ptr(tm+0x58)
        local flag=flags and memory.read(flags+ti,1)
        local phase=u32(memory.read(phases+wi*4,4),0)
        if not flag or not phase or flag:byte(1)>1 then return nil end
        local projectile,pi,_,projectile_identity=component(0x33266d8,0x50,0x68,weapon,8192)
        if not projectile or pi>=4096 or projectile_identity~=identity then return nil end
        local records=ptr(projectile+0x78)
        local record=records and memory.read(records+pi*0xa8,0xa8)
        if not record then return nil end
        local count=u32(record,0x3c)
        local function float_at(offset)
            ffi.copy(f,record:sub(offset+1,offset+4),4);return tonumber(f[0])
        end
        local cooldown,interval=float_at(8),float_at(12)
        if not count or count>100000 or cooldown~=cooldown or interval~=interval
            or interval<0.005 or interval>5 then return nil end
        return {manager=wm,avatar=id,key=avatar..identity,weapon=weapon,slot=0,
            has_charge=charge,mode=mode,phase=bit.band(phase,7),active=flag:byte(1)==1,
            input_held=input_held,shots=count,cooldown=cooldown,interval=interval}
    end
    function api.start(s)request(ffi.cast('void *',s.manager),s.avatar,s.slot)end
    function api.stop(s)release(ffi.cast('void *',s.manager),s.avatar,s.slot)end
    return api
end

end)()
local signatures={[7891936]="\072\137\076\036\008\083\085\086\087\065\084\072\131\236\048\072\139\061\042\248\185\002\069\051\201\059\021\033\208\207\002\076\137\108\036\104\076\137\116\036\040\076\137\124\036\032\069\139\248\116\062\068\139\087\056\069\139\193\139\095\064\015\175\218",[7892464]="\064\083\087\065\084\065\087\072\131\236\040\068\139\013\030\206\207\002\069\051\210\072\137\108\036\088\072\139\249\072\137\116\036\096\076\137\108\036\104\076\137\116\036\032\069\139\224\065\059\209\116\062\068\139\089\056\069\139\194\139\089\064\015\175",[5282368]="\072\131\236\040\076\139\209\072\133\201\117\007\051\192\072\131\196\040\195\139\065\008\059\005\200\161\247\002\015\132\147\000\000\000\076\139\029\119\210\225\002\069\051\192\072\137\092\036\048\072\137\108\036\056\072\137\116\036\064\069\139\075\120\065"}
if rawget(_G,'SuzukaSemiHold') then return end
local state={version='1.0.0',status='STARTING',errors=0,rate_factor=1,semi_enabled=true,menu='WAITING'}
rawset(_G,'SuzukaSemiHold',state)
local loader=rawget(_G,'CowboyBingusModLoader')
local last_written
local function text()
    local lines={'VERSION='..state.version,'STATUS='..state.status,'RUNTIME_VERIFIED=false',
        'RATE_FACTOR='..state.rate_factor,'MENU='..state.menu,'SEMI_ENABLED='..tostring(state.semi_enabled)}
    if state.menu_error then lines[#lines+1]='MENU_ERROR='..tostring(state.menu_error) end
    if state.policy then lines[#lines+1]='REQUESTS='..state.policy.requests..' RELEASES='..state.policy.resets end
    if state.error then lines[#lines+1]='ERROR='..tostring(state.error) end
    return table.concat(lines,'\n')..'\n'
end
-- Writes only when the content changed; an idle session performs no file operations.
local function log()
    if not loader or not loader.open_log then return end
    local content=text()
    if content==last_written then return end
    local f=loader.open_log('SuzukaSemiHold.log');if not f then return end
    f:write(content);f:close()
    last_written=content
end
local ok,problem=pcall(function()
    assert(loader and loader.api==1,'BSL_API_1_REQUIRED')
    local memory=create_memory()
    local game=assert(memory.module('game.dll'),'GAME_DLL_MISSING')
    assert(memory.module_hash(game)==GAME_SHA,'UNSUPPORTED_DLL_NO_CALLS')
    assert(memory.module_hash(assert(memory.module(nil)))==EXE_SHA,'UNSUPPORTED_EXE_NO_CALLS')
    local register_menu=create_menu(state)
    state.policy=policy.new(create_runtime(memory,game,signatures),state)
    local previous=assert(rawget(_G,'update'),'UPDATE_CALLBACK_REQUIRED')
    local old_shutdown=rawget(_G,'shutdown')
    local function step() register_menu();state.policy:step() end
    local frames=0
    local log_pending=false
    local wrapper
    wrapper=function(...)
        if state.errors==0 then
            local good,err=pcall(step)
            if good then state.status=state.policy.status
            else state.error=err;state.errors=1;state.policy:shutdown();state.status='DISABLED_RUNTIME_ERROR';log() end
        end
        frames=frames+1
        if frames%300==0 then log_pending=true end
        -- File writes wait until no repeat is armed, so they never land between shots.
        if log_pending and not state.policy.armed then log();log_pending=false end
        return previous(...)
    end
    rawset(_G,'update',wrapper)
    rawset(_G,'shutdown',function(...)
        state.policy:shutdown();state.status='SHUTDOWN';log()
        if rawget(_G,'update')==wrapper then rawset(_G,'update',previous)end
        if old_shutdown then return old_shutdown(...)end
    end)
    state.status='READY';log()
end)
if not ok then state.status='DISABLED_NO_CALLS';state.error=problem;log()end
