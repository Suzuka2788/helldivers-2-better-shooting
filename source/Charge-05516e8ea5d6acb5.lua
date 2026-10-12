-- HD2-Addon: mods/tongz/charge_auto_cycle
local GAME_SHA="2e2c3b7c2500646dadd5f2b4c6e0504dbb7e7896139f64cddc0d1813c718f51e"
local EXE_SHA="f5fee03dcfdb2e553a4752c283590950ac13316b376d8196aa556ff0400d5f06"
local create_memory=(function()
-- Read-only Windows adapter (same as Burst-Hold preview10): reads use ReadProcessMemory only.
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
-- Follow a native first charge; release at the engine's current full threshold.
local M={}
-- allowed(weapon_type): per-weapon toggle; nil allows every weapon.
function M.new(api,allowed)
    local s={status='IDLE',requests=0,resets=0,blocked=false}
    local function same(a,b)
        return a and b and a.key==b.key and a.weapon==b.weapon
            and a.manager==b.manager and a.slot==b.slot and a.mode==b.mode
    end
    local function release(current,now,status)
        api.stop(current)
        s.resets=s.resets+1
        s.restart_at=now+0.05
        s.stage='release'
        s.status=status
    end
    function s:shutdown() self.armed=nil;self.blocked=true end
    function s:step()
        if not api.down() then
            self.armed=nil;self.blocked=true;self.status='FOCUS_LOST_RELEASE_TO_REARM';return
        end
        -- While blocked only a release matters, so ask for the input state only.
        local c=api.snapshot(self.blocked)
        -- Input-only answers carry no native fields; keep the last full one for logs.
        self.fresh=c and c.full~=nil or false
        if self.fresh or not c then self.observed=c end
        if not c then
            if self.armed then self.blocked=true;self.armed=nil end
            self.status='GUARD_IDLE';return
        end
        if not c.input_held then
            self.armed=nil;self.blocked=false;self.stage=nil;self.previous_charge=nil;self.full_since=nil
            self.status='RELEASED';return
        end
        if self.blocked then self.status='RELEASE_TO_REARM';return end
        -- A switched-off weapon is left fully native until Fire is released.
        if allowed and not allowed(c.weapon_type) then
            self.armed=nil;self.blocked=true;self.status='WEAPON_DISABLED_RELEASE_TO_REARM';return
        end
        if self.armed and not same(c,self.armed) then
            self.armed=nil;self.blocked=true;self.status='WEAPON_CHANGED_RELEASE_TO_REARM';return
        end
        local now=api.now()
        if not self.armed then
            if c.charging and c.active and c.charge>0 then
                self.armed=c;self.stage='charge';self.previous_charge=c.charge;self.full_since=nil
                self.deadline=now+math.max(10,c.full*3)
                self.status='ARMED'
            else self.status='WAITING_FOR_NATIVE_FIRST_CHARGE' end
            return
        end
        if now>self.deadline then
            self.armed=nil;self.blocked=true;self.status='STALLED_RELEASE_TO_REARM';return
        end
        if self.stage=='release' then
            -- Per-trigger shot count is cleared by release; use native reset.
            if c.charge>0.001 or c.charging or c.cooldown>0 or c.phase~=0 or c.active then
                self.status='WAITING_FOR_NATIVE_RESET';return
            end
            if now<self.restart_at then self.status='WAITING_RELEASE_FRAME';return end
            api.start(c);self.requests=self.requests+1;self.stage='pending'
            self.deadline=now+math.max(10,c.full*3);self.status='REQUESTED_NEXT_CHARGE';return
        end
        if self.stage=='pending' then
            if not c.charging or c.charge<=0 then self.status='WAITING_FOR_CHARGE';return end
            self.stage='charge'
            self.full_since=nil
        end
        if c.charging and c.charge>=c.full-0.0001 then
            self.full_since=self.full_since or now
            if now-self.full_since<0.05-0.000001 then
                self.status='FULL_CHARGE_DELAY';return
            end
            release(c,now,'RELEASE_FULL_CHARGE')
            self.full_since=nil
            self.deadline=now+10;return
        end
        self.full_since=nil
        -- Native auto-fire can reset charge before this addon releases.
        if self.previous_charge and self.previous_charge>0.01 and c.charge<=0.001 and not c.charging then
            release(c,now,'NATIVE_CHARGE_RESET');return
        end
        self.previous_charge=c.charge
        self.status='CHARGING'
    end
    return s
end
return M

end)()
local create_runtime=(function()
-- Known-build native adapter. No weapon-stat or executable-page writes.
return function(memory,game,signatures)
    local ffi,bit=require('ffi'),require('bit')
    ffi.cdef[[void *GetForegroundWindow(void);
        uint32_t GetWindowThreadProcessId(void *,uint32_t *);
        uint32_t GetCurrentProcessId(void); uint64_t GetTickCount64(void);]]
    local user,kernel=ffi.load('user32'),ffi.load('kernel32')
    local pid=ffi.new('uint32_t[1]')
    local own_pid=kernel.GetCurrentProcessId()
    local function focused()
        local window=user.GetForegroundWindow()
        if window==nil then return false end
        user.GetWindowThreadProcessId(window,pid)
        return pid[0]==own_pid
    end
    local function u32(s,o)
        if not s or #s<o+4 then return nil end
        local a,b,c,d=s:byte(o+1,o+4)
        return a+b*256+c*65536+d*16777216
    end
    local f=ffi.new('float[1]')
    local function f32(s,o)ffi.copy(f,s:sub(o+1,o+4),4);return tonumber(f[0])end
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
    local charge_settings=ffi.cast('const uint8_t *(*)(const void *)',game+0x5052c0)
    local ARC_THROWER="\230\006\115\015\213\156\222\150"
    local SLOT_OFFSET={[1]=0,[2]=4,[3]=8,[6]=12}
    -- Shared answers for the input-only exits; the policy never stores them.
    local IDLE,HELD={input_held=false},{input_held=true}
    local api={}
    api.guard_misses={}
    local function miss(label)
        api.guard_misses[label]=(api.guard_misses[label] or 0)+1
        api.last_miss=label
        return nil
    end
    function api.now()return tonumber(kernel.GetTickCount64())/1000 end
    function api.down()
        return focused()
    end
    -- Fire not held: return IDLE right after the input read, skipping the
    -- weapon/charge chain (~25 reads and the settings call). input_only=true
    -- (policy waiting for a re-press) also stops there with HELD. A full
    -- snapshot reads exactly the same sequence as preview5.
    function api.snapshot(input_only)
        local owner,pm=ptr(game+0x3326b90),ptr(game+0x3326468)
        if not owner or not pm then return miss('owner_or_player_manager') end
        local net=u32(memory.read(pm+0x3a8,4),0)
        if not net or net==0 or net==0x7fff or net==0xffffffff then return miss('player_net_id') end
        local ei=lookup(owner+0xf21a88,net,1048576)
        if not ei or ei>=262144 then return miss('owner_entity_index') end
        local avatar=memory.read(owner+0xf31ad8+ei*24,24)
        if not avatar or avatar:sub(1,8)~='\151\250\77\41\77\51\28\77'
            or u32(avatar,16)~=net or bit.band(avatar:byte(21),3)~=1 then return miss('avatar_identity') end
        local id=u32(avatar,8)
        local am=ptr(game+0x3326d20)
        local ai=am and lookup(am+0xf8,id,64)
        -- AvatarManager embeds its entity-pointer slots at +0x110.
        local ae=ai and ptr(am+0x110+ai*8)
        local aid=ae and memory.read(ae,24)
        if not am or not ai or ai>=8 or aid~=avatar then return miss('avatar_manager') end
        local fire=memory.read(am+0x150+ai*0xa7aec+0x1b68+9*32,32)
        if not fire then return miss('fire_input') end
        local held=f32(fire,8)
        local input_held=fire:byte(1)~=0 and held>0 and held<86400
        if not input_held then return IDLE end
        if input_only then return HELD end
        local wm,wi,_,wid=component(0x3326420,0x30,0x48,id,8192)
        if not wm or wi>=4096 or wid~=avatar then return miss('wielder') end
        local slots=ptr(wm+0x60);local requests=ptr(wm+0x58);local phases=ptr(wm+0x68)
        if not slots or not requests or not phases then return miss('wielder_arrays') end
        local weapon=u32(memory.read(slots+wi*0x1d0,4),0)
        if not weapon or weapon==0 or weapon==0xffffffff then return miss('held_weapon') end
        -- Equipment confirms slot zero is the actually selected handheld gun.
        local im,ii=component(0x3326738,0x28,0x40,id,4096)
        local inventory=im and ptr(im+0x50)
        local inv=inventory and memory.read(inventory+ii*48,48)
        if not inv then return miss('inventory') end
        local offset=SLOT_OFFSET[u32(inv,28)]
        if not offset or u32(inv,offset)~=weapon then return miss('selected_slot') end
        local dm,di,entity,identity=component(0x3326ce0,0x30,0x48,weapon,32768)
        if not dm or di>=8192 then return miss('fire_mode_manager') end
        local modes=ptr(dm+0x60)
        local mode=modes and u32(memory.read(modes+di*12,4),0)
        if not mode or mode>8 then return miss('fire_mode') end
        local cm,ci,charge_entity,cid=component(0x3326c20,0x20,0x38,weapon,8192)
        if not cm or ci>=512 or cid~=identity then return miss('charge_component') end
        local tm,ti,_,tid=component(0x3326660,0x28,0x40,weapon,8192)
        if not tm or ti>=4096 or tid~=identity then return miss('trigger_component') end
        local flags=ptr(tm+0x58)
        local flag=flags and memory.read(flags+ti,1)
        local phase=u32(memory.read(phases+wi*4,4),0)
        if not flag or not phase or flag:byte(1)>1 then return miss('trigger_flag_phase') end
        local count,cooldown,interval=0,0,nil
        local projectile,pi,_,projectile_identity=component(0x33266d8,0x50,0x68,weapon,8192)
        if projectile or identity:sub(1,8)~=ARC_THROWER then
            if not projectile or pi>=4096 or projectile_identity~=identity then return miss('projectile_component') end
            local records=ptr(projectile+0x78)
            local record=records and memory.read(records+pi*0xa8,0xa8)
            if not record then return miss('projectile_record') end
            count=u32(record,0x3c)
            cooldown,interval=f32(record,8),f32(record,12)
            if not count or count>100000 or cooldown~=cooldown or interval~=interval
                or interval<0.005 or interval>5 then return miss('projectile_values') end
        end
        local entries=ptr(cm+0x40)
        local charge=entries and memory.read(entries+ci*40,40)
        if not charge then return miss('charge_entry') end
        local value,previous_charge=f32(charge,4),f32(charge,8)
        local config=charge_settings(ffi.cast('void *',charge_entity))
        if config==nil then return miss('charge_settings') end
        local times=memory.read(tonumber(ffi.cast('uintptr_t',config)),52)
        if not times then return miss('charge_times') end
        local minimum,full,overcharge=f32(times,0),f32(times,24),f32(times,48)
        if minimum~=minimum or overcharge~=overcharge or minimum<0 or minimum>full
            or overcharge<full or overcharge>60 then return miss('charge_time_range') end
        local charging=charge:byte(13)
        if value~=value or full~=full or value<0 or full<=0.01 or full>30
            or value>60 or charging>1 then return miss('charge_values') end
        -- Entity identity starts with the weapon's resource-name hash (per-weapon toggles).
        return {manager=wm,avatar=id,key=avatar..identity,weapon=weapon,slot=0,weapon_type=identity:sub(1,8),
            mode=mode,phase=bit.band(phase,7),active=flag:byte(1)==1,
            input_held=input_held,shots=count,cooldown=cooldown,interval=interval,
            charge=value,full=full,minimum=minimum,overcharge=overcharge,
            previous_charge=previous_charge,charging=charging==1}
    end
    function api.start(s)request(ffi.cast('void *',s.manager),s.avatar,s.slot)end
    function api.stop(s)release(ffi.cast('void *',s.manager),s.avatar,s.slot)end
    return api
end

end)()
local create_toggles=(function()
-- Per-weapon on/off rows in Mod Options Menu; the menu owns persistence.
-- Hashes are the weapons' resource-name hashes (first 8 bytes of the entity
-- identity), matched against all-resources.txt paths and earlier mods.
local WEAPONS={
    {key='arc3',high=0x96DE9CD5,low=0x0F7306E6,label='ARC-3 电弧发射器',default=true},   -- arc_thrower
    {key='epoch',high=0xE8D5F49A,low=0xD7780E54,label='PLAS-45 纪元',default=false},     -- plasma_blaster
    {key='railgun',high=0x2E9D0BDC,low=0x48B09E60,label='RS-422 磁轨炮',default=false},  -- railgun
    {key='purifier',high=0xFB3A1907,low=0x8694708A,label='PLAS-101 净化者',default=true},
    {key='accelerator',high=0x30061F91,low=0xAF477F5E,label='PLAS-39 加速步枪',default=true}, -- sniper_rifle_helghast
    {key='loyalist',high=0xAA69A60D,low=0x74A3EC54,label='PLAS-15 忠诚者',default=true},  -- plasma_pistol
}
local OTHER={key='other',label='其他充能武器',default=true}
local function le(high,low)
    local out={}
    for _,word in ipairs({low,high}) do
        for i=0,3 do out[#out+1]=string.char(math.floor(word/2^(8*i))%256) end
    end
    return table.concat(out)
end
return function(state)
    local enabled,by_type,rows={},{},{}
    for _,w in ipairs(WEAPONS) do by_type[le(w.high,w.low)]=w.key;rows[#rows+1]=w end
    rows[#rows+1]=OTHER
    for _,w in ipairs(rows) do enabled[w.key]=w.default end
    state.toggles=enabled;state.menu='WAITING'
    local ticks=0
    local s={}
    function s.kind(weapon_type)return by_type[weapon_type] or 'other' end
    function s.allowed(weapon_type)return enabled[by_type[weapon_type] or 'other'] end
    function s.tick()
        if state.menu~='WAITING' then return end
        ticks=ticks+1
        local menu=rawget(_G,'ModOptionsMenu')
        if not menu then
            if ticks>=1200 then state.menu='UNAVAILABLE_DEFAULTS' end
            return
        end
        if type(menu)~='table' or menu.api~=1 or type(menu.register_option)~='function'
            or type(menu.get)~='function' or type(menu.on_change)~='function' then
            state.menu='INCOMPATIBLE_DEFAULTS';return
        end
        for _,w in ipairs(rows) do
            local id='tongz_charge_auto_cycle.'..w.key
            local function apply(value) if type(value)=='boolean' then enabled[w.key]=value end end
            local ok,reason=menu.register_option(id,{type='toggle',mod='Suzuka Better Shooting',mod_id='suzuka.shooting_experience_optimization',
                label=w.label,default=w.default,
                description=w==OTHER and '未单独列出的充能武器（含未识别型号）。默认开。'
                    or ('按住开火时自动满蓄力循环。默认'..(w.default and '开' or '关')..'。改动在下一次按下开火时生效。')})
            if not ok then state.menu='REGISTER_FAILED';state.menu_error=reason;return end
            apply(menu.get(id))
            menu.on_change(id,apply)
        end
        state.menu='REGISTERED'
    end
    function s.text()
        local parts={}
        for _,w in ipairs(rows) do parts[#parts+1]=w.key..'='..(enabled[w.key] and '1' or '0') end
        return table.concat(parts,' ')
    end
    return s
end

end)()
local signatures={[7891936]="\072\137\076\036\008\083\085\086\087\065\084\072\131\236\048\072\139\061\042\248\185\002\069\051\201\059\021\033\208\207\002\076\137\108\036\104\076\137\116\036\040\076\137\124\036\032\069\139\248\116\062\068\139\087\056\069\139\193\139\095\064\015\175\218",[7892464]="\064\083\087\065\084\065\087\072\131\236\040\068\139\013\030\206\207\002\069\051\210\072\137\108\036\088\072\139\249\072\137\116\036\096\076\137\108\036\104\076\137\116\036\032\069\139\224\065\059\209\116\062\068\139\089\056\069\139\194\139\089\064\015\175"}
signatures[0x5052c0]="\072\131\236\040\076\139\209\072\133\201\117\007\051\192\072\131\196\040\195\139\065\008\059\005\072\233\247\002\015\132\147\000\000\000\076\139\029\055\025\226\002\069\051\192\072\137\092\036\048\072\137\108\036\056\072\137\116\036\064\069\139\075\088\065"
if rawget(_G,'TongzChargeAutoCycle') then return end
local state={version='0.1.6-preview7-toggles',status='STARTING',errors=0,events={}}
rawset(_G,'TongzChargeAutoCycle',state)
local loader=rawget(_G,'CowboyBingusModLoader')
local ffi=require('ffi')
pcall(ffi.cdef,'int QueryPerformanceCounter(int64_t *); int QueryPerformanceFrequency(int64_t *);')
local kernel=ffi.load('kernel32')
local tick=ffi.new('int64_t[1]')
kernel.QueryPerformanceFrequency(tick)
local ms_per_tick=1000/tonumber(tick[0])
local function ticks() kernel.QueryPerformanceCounter(tick);return tonumber(tick[0]) end
-- Timing covers frames whose policy status is not RELEASED (Fire held or a cycle pending).
local perf={frames=0,ticks=0,max=0,over1=0,over4=0}
local memory_stats
local toggles=create_toggles(state)
local last_written
local function text()
    local lines={'VERSION='..state.version,'STATUS='..state.status,'RUNTIME_VERIFIED=false',
        'ERRORS='..state.errors,'MENU='..state.menu,'WEAPON_TOGGLES '..toggles.text()}
    if state.menu_error then lines[#lines+1]='MENU_ERROR='..tostring(state.menu_error) end
    if state.policy then
        lines[#lines+1]='REQUESTS='..state.policy.requests..' RELEASES='..state.policy.resets
        local c=state.policy.observed
        if c then lines[#lines+1]=string.format('NATIVE kind=%s weapon=%d mode=%d charge=%.4f full=%.4f shots=%d phase=%d cooldown=%.4f charging=%s active=%s input=%s',
            toggles.kind(c.weapon_type),c.weapon,c.mode,c.charge,c.full,c.shots,c.phase,c.cooldown,
            tostring(c.charging),tostring(c.active),tostring(c.input_held)) end
        if c and c.minimum then lines[#lines+1]=string.format('CHARGE_CONFIG minimum=%.4f full=%.4f overcharge=%.4f previous_charge=%.4f full_delay_ms=50',
            c.minimum,c.full,c.overcharge,c.previous_charge) end
    end
    if perf.frames>0 then
        lines[#lines+1]=string.format('PERF active_frames=%d avg_ms=%.4f max_ms=%.3f over_1ms=%d over_4ms=%d',
            perf.frames,perf.ticks*ms_per_tick/perf.frames,perf.max*ms_per_tick,perf.over1,perf.over4)
    end
    if memory_stats then
        lines[#lines+1]='PERF_READS reads='..memory_stats.reads..' failed='..memory_stats.failed
            ..' per_active_frame='..string.format('%.1f',memory_stats.reads/math.max(perf.frames,1))
    end
    if state.runtime then
        local misses={}
        for _,label in ipairs({'owner_or_player_manager','player_net_id','owner_entity_index','avatar_identity','avatar_manager','fire_input','wielder','wielder_arrays','held_weapon','inventory','selected_slot','fire_mode_manager','fire_mode','charge_component','trigger_component','trigger_flag_phase','projectile_component','projectile_record','projectile_values','charge_entry','charge_settings','charge_times','charge_time_range','charge_values'}) do
            local n=state.runtime.guard_misses[label]
            if n then misses[#misses+1]=label..':'..n end
        end
        lines[#lines+1]='GUARD_MISSES='..(#misses>0 and table.concat(misses,' ') or 'none')
            ..' LAST='..tostring(state.runtime.last_miss)
    end
    for _,event in ipairs(state.events) do lines[#lines+1]='EVENT='..event end
    if state.error then lines[#lines+1]='ERROR='..tostring(state.error):gsub('[\r\n]',' ') end
    return table.concat(lines,'\n')..'\n'
end
-- Writes only when the content changed; frames spent RELEASED perform no file operations.
local function log()
    if not loader or not loader.open_log then return end
    local content=text()
    if content==last_written then return end
    local f=loader.open_log('TongzChargeAutoCycle.log')
    if not f then return end
    f:write(content)
    f:close()
    last_written=content
end
local ok,problem=pcall(function()
    assert(loader and loader.api==1,'BSL_API_1_REQUIRED')
    local memory=create_memory()
    memory_stats=memory.stats
    local game=assert(memory.module('game.dll'),'GAME_DLL_MISSING')
    local exe=assert(memory.module(nil),'EXE_MISSING')
    assert(memory.module_hash(exe)==EXE_SHA,'UNSUPPORTED_EXE_NO_CALLS')
    assert(memory.module_hash(game)==GAME_SHA,'UNSUPPORTED_DLL_NO_CALLS')
    state.runtime=create_runtime(memory,game,signatures)
    state.policy=policy.new(state.runtime,toggles.allowed)
    local function step() toggles.tick();state.policy:step() end
    local previous=assert(rawget(_G,'update'),'UPDATE_CALLBACK_REQUIRED')
    local previous_shutdown=rawget(_G,'shutdown')
    local frames=0
    local log_pending=false
    local wrapper
    wrapper=function(...)
        if state.errors==0 then
            local began=ticks()
            local good,err=pcall(step)
            local spent=ticks()-began
            if not good then
                state.errors=state.errors+1;state.error=err
                state.policy:shutdown();state.status='DISABLED_RUNTIME_ERROR'
            else state.status=state.policy.status end
            if state.status~='RELEASED' then
                perf.frames=perf.frames+1;perf.ticks=perf.ticks+spent
                if spent>perf.max then perf.max=spent end
                local ms=spent*ms_per_tick
                if ms>1 then perf.over1=perf.over1+1 end
                if ms>4 then perf.over4=perf.over4+1 end
            end
        end
        frames=frames+1
        if state.last_status~=state.status then
            local c=state.policy.fresh and state.policy.observed
            local detail=c and string.format(' charge=%.4f full=%.4f phase=%d active=%s charging=%s cooldown=%.4f shots=%d',
                c.charge,c.full,c.phase,tostring(c.active),tostring(c.charging),c.cooldown,c.shots) or ''
            state.events[#state.events+1]=frames..':'..state.status..detail
            if #state.events>16 then table.remove(state.events,1) end
            state.last_status=state.status
        end
        if frames%300==0 then log_pending=true end
        -- File writes wait until no charge cycle is armed, so they never land
        -- inside the 50 ms full-charge window or a pending re-request.
        if state.status=='DISABLED_RUNTIME_ERROR' and not state.error_logged then
            log();state.error_logged=true;log_pending=false
        elseif log_pending and not state.policy.armed then
            log();log_pending=false
        end
        return previous(...)
    end
    rawset(_G,'update',wrapper)
    rawset(_G,'shutdown',function(...)
        state.policy:shutdown();state.status='SHUTDOWN';log()
        if rawget(_G,'update')==wrapper then rawset(_G,'update',previous) end
        if previous_shutdown then return previous_shutdown(...) end
    end)
    state.status='WAITING_FOR_NATIVE_FIRST_CHARGE';log()
end)
if not ok then state.status='DISABLED_NO_CALLS';state.error=problem;log() end
