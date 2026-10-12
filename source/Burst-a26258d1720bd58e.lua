-- HD2-Addon: mods/tongz/burst_hold
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
-- Native requests are issued only between bursts, after an ordinary first shot.
local M = {}
function M.new(api,options)
    options=options or {pause_ms=270}
    local s = {status='IDLE',requests=0,cancels=0,resets=0,armed=nil,pending=nil,blocked=false}
    local function same(a,b)
        return a and b and a.key==b.key and a.weapon==b.weapon
            and a.manager==b.manager and a.slot==b.slot
    end
    function s:cancel()
        if not self.pending then return true end
        local current=api.snapshot()
        if not current then self.status='WAITING_TO_CANCEL';return false end
        if same(current,self.pending) and (current.phase==1 or current.phase==3) then
            api.stop(current);self.cancels=self.cancels+1
        end
        self.pending=nil
        return true
    end
    function s:step()
        local down=api.down()
        if not down then
            self.armed=nil;self.blocked=false;self.resetting=false;self.next_burst_at=nil
            self:cancel()
            if not self.pending then self.status='RELEASED' end
            return
        end
        if self.blocked then self:cancel();self.status='RELEASE_TO_REARM';return end
        -- false: guard-only early exit; keep the last full native state for the log.
        local current=api.snapshot(true)
        if current~=false then self.observed=current end
        if not current or not current.input_held or current.mode~=3 or current.rounds~=3 then
            if self.armed or self.pending then
                self:cancel();self.armed=nil;self.blocked=true
            end
            self.status='GUARD_IDLE';return
        end
        if self.armed and not same(current,self.armed) then
            self:cancel();self.armed=nil;self.blocked=true
            self.status='WEAPON_CHANGED_RELEASE_TO_REARM';return
        end
        -- Seeing state 4 with native activation proves the game accepted Fire.
        if not self.armed then
            if current.phase==4 and current.active then
                self.armed=current;self.status='ARMED'
            else self.status='WAITING_FOR_NATIVE_FIRST_BURST' end
            return
        end
        if self.resetting then
            if current.phase~=0 or current.active or current.shots~=0 then
                self.status='WAITING_FOR_NATIVE_RESET';return
            end
            -- The native shot cooldown keeps counting down after release; never request before it ends.
            if api.now()<self.next_burst_at or current.cooldown>0 then
                self.status='BURST_PAUSE';return
            end
            self.resetting=false
            self.next_burst_at=nil
        elseif current.phase==4 then
            self.pending=nil
            -- Release on the frame the third shot is counted. Holding the trigger through
            -- the third shot's cooldown let looping fire audio play a fourth shot sound.
            -- The cooldown moves to the next-request wait, so group cadence is unchanged.
            if current.shots==3 then
                api.stop(current);self.resets=self.resets+1;self.resetting=true
                self.next_burst_at=api.now()+math.max(current.cooldown,0)+options.pause_ms/1000
                self.status='RELEASE_COMPLETED_BURST';return
            end
            self.status='NATIVE_BURST';return
        end
        -- Never restart a pending request, charge, reload, or an active burst.
        if current.phase~=0 or current.active then self.status='NATIVE_BUSY';return end
        self.pending=current
        api.start(current)
        self.requests=self.requests+1;self.status='REQUESTED_NEXT_BURST'
    end
    function s:shutdown()
        self.armed=nil;self.blocked=true
        return self:cancel()
    end
    return s
end
return M

end)()
local create_menu=(function()
return function(state)
    local id='tongz_burst_hold.pause_ms'
    local ticks=0
    local function apply(value)
        if type(value)=='number' and value==value and value>=0 and value<=1000 then
            state.pause_ms=math.floor(value/10+0.5)*10
        end
    end
    return function()
        if state.menu~='WAITING' then return end
        ticks=ticks+1
        local menu=rawget(_G,'ModOptionsMenu')
        if not menu then
            if ticks>=1200 then state.menu='UNAVAILABLE' end
            return
        end
        if type(menu)~='table' or menu.api~=1 or type(menu.register_option)~='function'
            or type(menu.get)~='function' or type(menu.on_change)~='function' then
            state.menu='INCOMPATIBLE';return
        end
        local ok,reason=menu.register_option(id,{type='slider',mod='Suzuka Better Shooting',mod_id='suzuka.shooting_experience_optimization',
            label='BURST PAUSE (MS)',min=0,max=1000,step=10,default=270,
            description='Extra pause after each native three-round burst, in milliseconds. Default: 270 ms. Apply to save; takes effect after the next completed burst.'})
        if not ok then state.menu='REGISTER_FAILED';state.menu_error=reason;return end
        apply(menu.get(id))
        menu.on_change(id,apply)
        state.menu='REGISTERED'
    end
end

end)()
local create_trace=(function()
-- preview9 diagnostic: per-group native state transitions, read from the policy's
-- existing snapshot. No extra memory reads; one entry only when a field changes.
local MAX_GROUPS,MAX_MARKED,MAX_ENTRIES=12,20,48
return function()
    local t={groups={},marked={},marks=0,count=0}
    local group,last,marker_down
    local function close()
        if not group then return end
        t.groups[#t.groups+1]=group
        if #t.groups>MAX_GROUPS then table.remove(t.groups,1) end
        group=nil
    end
    local function line(g)
        return 'GROUP='..g.id..(g.marked and ' MARKED' or '')..' '..table.concat(g.entries,' ')
    end
    -- policy: the burst policy; ms: QPC milliseconds; marker: F8 held this frame.
    function t:step(policy,ms,marker)
        if marker and not marker_down then
            self.marks=self.marks+1
            -- The sound may belong to the running group or the one that just ended.
            local target=group or self.groups[#self.groups]
            local previous=group and self.groups[#self.groups]
            for _,g in ipairs({target,previous}) do
                if g and not g.marked then
                    g.marked=true
                    g.entries[#g.entries+1]=string.format('F8@%.0f',ms-g.started)
                    self.marked[#self.marked+1]=g
                    if #self.marked>MAX_MARKED then table.remove(self.marked,1) end
                end
            end
        end
        marker_down=marker
        local s=policy.observed
        if not policy.armed or not s then close();last=nil;return end
        if not last then t.requests,t.resets=policy.requests,policy.resets end
        local action
        if policy.requests~=t.requests then action='REQ' end
        if policy.resets~=t.resets then action=(action and action..'+' or '')..'REL' end
        t.requests,t.resets=policy.requests,policy.resets
        if not group or action=='REQ' then
            close()
            self.count=self.count+1
            group={id=self.count,started=ms,frames=0,entries={}}
        end
        group.frames=group.frames+1
        local key=s.phase..(s.active and 'A' or 'a')..s.shots..'f'..tostring(s.fire_ready)..'t'..tostring(s.trigger)
        if key~=last or action then
            if #group.entries<MAX_ENTRIES then
                group.entries[#group.entries+1]=string.format('%s%d/%.1f:p%d%s s%d f%s t%s cd%.3f sp%.3f',
                    action and action..'@' or '',group.frames,ms-group.started,s.phase,s.active and 'A' or 'a',
                    s.shots,tostring(s.fire_ready),tostring(s.trigger),s.cooldown,s.spin or 0)
            end
            last=key
        end
    end
    function t:lines()
        local out={'TRACE groups='..self.count..' marks='..self.marks
            ..' format=[action@]frame/ms:p<phase><A=active> s<shots> f<fire_ready> t<trigger> cd<cooldown> sp<spin>'}
        for _,g in ipairs(self.marked) do out[#out+1]='MARKED_'..line(g) end
        for _,g in ipairs(self.groups) do out[#out+1]=line(g) end
        if group then out[#out+1]=line(group)..' (open)' end
        return out
    end
    return t
end

end)()
local create_runtime=(function()
-- Known-build native adapter. No weapon-stat or executable-page writes.
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
    local settings=ffi.cast('const uint8_t *(*)(const void *)',game+0x509a40)
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
    -- preview9 diagnostic: F8 marks the group whose sound was wrong.
    function api.marker()
        return bit.band(tonumber(user.GetAsyncKeyState(0x77)),0x8000)~=0 and focused()
    end
    -- guard=true returns false as soon as the hold cannot qualify (input not
    -- held, fire mode or round count not three-round burst), skipping the
    -- Trigger and ProjectileWeapon lookups. Full snapshots are unchanged.
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
        local dm,di,entity,identity=component(0x3326ce0,0x30,0x48,weapon,32768)
        if not dm or di>=8192 then return nil end
        local modes=ptr(dm+0x60)
        local mode=modes and u32(memory.read(modes+di*12,4),0)
        if not mode or mode>8 then return nil end
        if guard and mode~=3 then return false end
        local config=settings(ffi.cast('void *',entity))
        if config==nil then return nil end
        local config_address=tonumber(ffi.cast('uintptr_t',config))
        local baseline=memory.read(config_address+140,20)
        if not baseline or u32(baseline,0)<1 or u32(baseline,0)>16 then return nil end
        if guard and (mode~=3 or u32(baseline,0)~=3) then return false end
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
            mode=mode,rounds=u32(baseline,0),phase=bit.band(phase,7),active=flag:byte(1)==1,
            input_held=input_held,shots=count,cooldown=cooldown,interval=interval,
            -- Diagnostic only: run record +0 fire-ready byte, +1 trigger byte, +4 spin timer.
            fire_ready=record:byte(1),trigger=record:byte(2),spin=float_at(4)}
    end
    function api.start(s)request(ffi.cast('void *',s.manager),s.avatar,s.slot)end
    function api.stop(s)release(ffi.cast('void *',s.manager),s.avatar,s.slot)end
    return api
end

end)()
local signatures={[7891936]="\072\137\076\036\008\083\085\086\087\065\084\072\131\236\048\072\139\061\042\248\185\002\069\051\201\059\021\033\208\207\002\076\137\108\036\104\076\137\116\036\040\076\137\124\036\032\069\139\248\116\062\068\139\087\056\069\139\193\139\095\064\015\175\218",[7892464]="\064\083\087\065\084\065\087\072\131\236\040\068\139\013\030\206\207\002\069\051\210\072\137\108\036\088\072\139\249\072\137\116\036\096\076\137\108\036\104\076\137\116\036\032\069\139\224\065\059\209\116\062\068\139\089\056\069\139\194\139\089\064\015\175",[5282368]="\072\131\236\040\076\139\209\072\133\201\117\007\051\192\072\131\196\040\195\139\065\008\059\005\200\161\247\002\015\132\147\000\000\000\076\139\029\119\210\225\002\069\051\192\072\137\092\036\048\072\137\108\036\056\072\137\116\036\064\069\139\075\120\065"}
if rawget(_G,'TongzBurstHold') then return end
local state={version='1.0.0',status='STARTING',errors=0,events={},pause_ms=270,menu='WAITING'}
rawset(_G,'TongzBurstHold',state)
local loader=rawget(_G,'CowboyBingusModLoader')
local ffi=require('ffi')
pcall(ffi.cdef,'int QueryPerformanceCounter(int64_t *); int QueryPerformanceFrequency(int64_t *);')
local kernel=ffi.load('kernel32')
local tick=ffi.new('int64_t[1]')
kernel.QueryPerformanceFrequency(tick)
local ms_per_tick=1000/tonumber(tick[0])
local function ticks() kernel.QueryPerformanceCounter(tick);return tonumber(tick[0]) end
-- Timing covers frames whose policy status is not RELEASED (button held or a cancel pending).
local perf={frames=0,ticks=0,max=0,over1=0,over4=0}
local memory_stats
local trace=create_trace()
local last_written
local function text()
    local lines={'VERSION='..state.version,'STATUS='..state.status,
        'MODE=NATIVE_BURST_REQUEST_PREVIEW RUNTIME_VERIFIED=false DIAGNOSTIC=F8_MARK',
        'BURST_PAUSE_MS='..state.pause_ms,'MENU='..state.menu}
    if state.menu_error then lines[#lines+1]='MENU_ERROR='..tostring(state.menu_error) end
    lines[#lines+1]='ERRORS='..state.errors
    if state.policy then
        lines[#lines+1]='REQUESTS='..state.policy.requests..' CANCELS='..state.policy.cancels..' RESETS='..state.policy.resets
        lines[#lines+1]='POLICY='..state.policy.status
        local s=state.policy.observed
        if s then lines[#lines+1]='LAST_NATIVE mode='..s.mode..' shots='..s.shots..' phase='..s.phase
            ..' active='..tostring(s.active)..' interval='..s.interval..' cooldown='..s.cooldown end
    end
    if perf.frames>0 then
        lines[#lines+1]=string.format('PERF held_frames=%d avg_ms=%.4f max_ms=%.3f over_1ms=%d over_4ms=%d',
            perf.frames,perf.ticks*ms_per_tick/perf.frames,perf.max*ms_per_tick,perf.over1,perf.over4)
    end
    if memory_stats then
        lines[#lines+1]='PERF_READS reads='..memory_stats.reads..' failed='..memory_stats.failed
            ..' per_held_frame='..string.format('%.1f',memory_stats.reads/math.max(perf.frames,1))
    end
    for _,event in ipairs(state.events) do lines[#lines+1]='EVENT='..event end
    for _,entry in ipairs(trace:lines()) do lines[#lines+1]=entry end
    if state.error then lines[#lines+1]='ERROR='..tostring(state.error):gsub('[\r\n]',' ') end
    return table.concat(lines,'\n')..'\n'
end
-- Writes only when the content changed; an idle session performs no file operations.
local function log()
    if not loader or not loader.open_log then return end
    local content=text()
    if content==last_written then return end
    local f=loader.open_log('TongzBurstHold.log')
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
    local register_menu=create_menu(state)
    register_menu()
    local native=create_runtime(memory,game,signatures)
    state.policy=policy.new(native,state)
    local previous=assert(rawget(_G,'update'),'UPDATE_CALLBACK_REQUIRED')
    local previous_shutdown=rawget(_G,'shutdown')
    local frames=0
    local log_pending=false
    local function step()
        register_menu();state.policy:step()
        trace:step(state.policy,ticks()*ms_per_tick,native.marker and native.marker())
    end
    local wrapper
    wrapper=function(...)
        local began=ticks()
        local good,err=pcall(step)
        local spent=ticks()-began
        if not good then
            state.errors=state.errors+1;state.error=err
            state.policy.blocked=true;state.policy.armed=nil
            state.status='ERROR_RELEASE_TO_REARM'
        else state.status=state.policy.status end
        if state.status~='RELEASED' then
            perf.frames=perf.frames+1;perf.ticks=perf.ticks+spent
            if spent>perf.max then perf.max=spent end
            local ms=spent*ms_per_tick
            if ms>1 then perf.over1=perf.over1+1 end
            if ms>4 then perf.over4=perf.over4+1 end
        end
        frames=frames+1
        if state.last_status~=state.status then
            state.events[#state.events+1]=frames..':'..state.status
            if #state.events>16 then table.remove(state.events,1) end
            state.last_status=state.status
        end
        if frames%300==0 then log_pending=true end
        if not good or (log_pending and not state.policy.armed and not state.policy.pending) then
            log();log_pending=false
        end
        return previous(...)
    end
    rawset(_G,'update',wrapper)
    rawset(_G,'shutdown',function(...)
        local good,err=pcall(function() state.policy:shutdown() end)
        state.status='SHUTDOWN'
        if not good then state.error=err;state.errors=state.errors+1 end
        log()
        if rawget(_G,'update')==wrapper then rawset(_G,'update',previous) end
        if previous_shutdown then return previous_shutdown(...) end
    end)
    state.status='WAITING_FOR_NATIVE_FIRST_BURST';log()
end)
if not ok then state.status='DISABLED_NO_CALLS';state.error=problem;log() end
