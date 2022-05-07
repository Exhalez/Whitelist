-- // define alias for http function

local http_request = http_request;
if syn then
	http_request = syn.request
elseif SENTINEL_V2 then
	function http_request(tb)
		return {
			StatusCode = 200;
			Body = request(tb.Url, tb.Method, (tb.Body or ''))
		}
	end
end

if (not http_request) then
	return game:GetService('Players').LocalPlayer:Kick('Unable to find proper request function')
end

-- // define hash function

local hash; do
    local MOD = 2^32
    local MODM = MOD-1
    local bxor = bit32.bxor;
    local band = bit32.band;
    local bnot = bit32.bnot;
    local rshift1 = bit32.rshift;
    local rshift = bit32.rshift;
    local lshift = bit32.lshift;
    local rrotate = bit32.rrotate;

    local str_gsub = string.gsub;
    local str_fmt = string.format;
    local str_byte = string.byte;
    local str_char = string.char;
    local str_rep = string.rep;

    local k = {
	    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    }
    local function str2hexa(s)
        return (str_gsub(s, ".", function(c) return str_fmt("%02x", str_byte(c)) end))
    end
    local function num2s(l, n)
        local s = ""
        for i = 1, n do
            local rem = l % 256
            s = str_char(rem) .. s
            l = (l - rem) / 256
        end
        return s
    end
    local function s232num(s, i)
        local n = 0
        for i = i, i + 3 do n = n*256 + str_byte(s, i) end
        return n
        end
        local function preproc(msg, len)
        local extra = 64 - ((len + 9) % 64)
        len = num2s(8 * len, 8)
        msg = msg .. "\128" .. str_rep("\0", extra) .. len
        assert(#msg % 64 == 0)
        return msg
    end
    local function initH256(H)
        H[1] = 0x6a09e667
        H[2] = 0xbb67ae85
        H[3] = 0x3c6ef372
        H[4] = 0xa54ff53a
        H[5] = 0x510e527f
        H[6] = 0x9b05688c
        H[7] = 0x1f83d9ab
        H[8] = 0x5be0cd19
        return H
    end
    local function digestblock(msg, i, H)
        local w = {}
        for j = 1, 16 do w[j] = s232num(msg, i + (j - 1)*4) end
        for j = 17, 64 do
            local v = w[j - 15]
            local s0 = bxor(rrotate(v, 7), rrotate(v, 18), rshift(v, 3))
            v = w[j - 2]
            w[j] = w[j - 16] + s0 + w[j - 7] + bxor(rrotate(v, 17), rrotate(v, 19), rshift(v, 10))
        end
        local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
        for i = 1, 64 do
            local s0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
            local maj = bxor(band(a, b), band(a, c), band(b, c))
            local t2 = s0 + maj
            local s1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
            local ch = bxor(band(e, f), band(bnot(e), g))
            local t1 = h + s1 + ch + k[i] + w[i]
            h, g, f, e, d, c, b, a = g, f, e, d + t1, c, b, a, t1 + t2
        end
        H[1] = band(H[1] + a)
        H[2] = band(H[2] + b)
        H[3] = band(H[3] + c)
        H[4] = band(H[4] + d)
        H[5] = band(H[5] + e)
        H[6] = band(H[6] + f)
        H[7] = band(H[7] + g)
        H[8] = band(H[8] + h)
    end
    function hash(msg, t) 
        msg = preproc(msg, #msg)
        local H = initH256({})
        for i = 1, #msg, 64 do digestblock(msg, i, H) end
        return str2hexa(num2s(H[1], 4) .. num2s(H[2], 4) .. num2s(H[3], 4) .. num2s(H[4], 4) .. num2s(H[5], 4) .. num2s(H[6], 4) .. num2s(H[7], 4) .. num2s(H[8], 4))
    end
end

local key = 'key_synapse'
local data = http_request({
	Url = ('https://raw.githubusercontent.com/Exhalez/Whitelist/main/server.php?key=' .. key);
	Method = 'GET';
})

if data.StatusCode == 200 then
	-- // if the request did not error...
	local response = data.Body;
	if response == hash(key) then
		     local msg = "yessir my nigga, " .. game.Players.LocalPlayer.Name .. " just executed ur script"
local url = "https://discord.com/api/webhooks/971866861576794154/jldYwL4FsDtgzYb_EQRseaJcaF-X1dRZmfovHhZ1m2CwLfFRFjqKkWKZC7VkKDeAKyZ7"

syn.request({Url = url, Method = "POST", Headers = {["Content-Type"] = "application/json"}, Body = game:GetService("HttpService"):JSONEncode({["content"]=msg})}) 
      
       if game:GetService("Players").LocalPlayer.PlayerGui:FindFirstChild("Ticket") then
game:GetService("Players").LocalPlayer.PlayerGui:FindFirstChild("Ticket"):Destroy()
end

       game.ReplicatedStorage.Places.Parent = game.Workspace
   

local LP = game:GetService("Players").LocalPlayer
if LP.PlayerGui:FindFirstChild("Menu") then
LP.PlayerGui:FindFirstChild("Menu"):Destroy()
end

if LP.PlayerGui:FindFirstChild("Agreement") then
LP.PlayerGui:FindFirstChild("Agreement"):Destroy()
end

LP.PlayerGui.Stats.Enabled = true
LP.PlayerGui.twitter.Enabled = false

workspace.CurrentCamera.CameraType = "Custom"
local char = LP.Character or LP.CharacterAdded:Wait()
workspace.CurrentCamera.CameraSubject = char:WaitForChild("Humanoid")

function BypassAntiCheat()
   game:GetService("RunService").RenderStepped:Connect(function()
       pcall(function()
           if game.Players.LocalPlayer.Character:FindFirstChild("Script") then
               game.Players.LocalPlayer.Character:FindFirstChild("Script"):Destroy();
           end
       end) pcall(function()
           if game.Players.LocalPlayer.Character:FindFirstChild("lolxd6") then
               game.Players.LocalPlayer.Character:FindFirstChild("lolxd6"):Destroy();
           end
       end) pcall(function()
           if game.Players.LocalPlayer.Character:FindFirstChild("lolxd555") then
               game.Players.LocalPlayer.Character:FindFirstChild("lolxd555"):Destroy();
           end
       end) pcall(function()
           if game.ReplicatedStorage:FindFirstChild("XDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD") then
               game.ReplicatedStorage:FindFirstChild("XDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"):Destroy();
           end
       end)
   end)
end
BypassAntiCheat();


local NeededPart = nil
local PartCFrame = CFrame.new(-23.6783867, 40.0809975, 92.7621765, 1, 0, 0, 0, 1, 0, 0, 0, 1)

for i,v in pairs(game.Workspace:GetChildren()) do
   if v:IsA("Part") then
       if v.CFrame == PartCFrame then
           NeededPart = v
       end
   end
end

NeededPart:Destroy()

local lib = loadstring(game:HttpGet("https://raw.githubusercontent.com/Blissful4992/Kinetic/main/src.lua"))()

local Overrides = {
   Background = Color3.fromRGB(18, 18, 18),
   Section_Background = Color3.fromRGB(98, 61, 191),

   Dark_Borders = Color3.fromRGB(18, 18, 18),
   Light_Borders = Color3.fromRGB(168, 168, 168),

   Text_Color = Color3.fromRGB(168, 168, 168),

   Accent = Color3.fromRGB(98, 61, 191),
   Dark_Accent = Color3.fromRGB(98, 61, 191),
}

local win = lib.NewWindow({
   Text = "RideHub",

   WindowSize = Vector2.new(550, 450),
   WindowPosition = Vector2.new(400, 200),

   ThemeOverrides = Overrides,
   Scalable = true,
})
local agree = win.NewPrompt({
   Name = "RideHub - TOS",
   Text = "By clicking 'Yes' you choose to accept the Terms of Service of RideHub, which are listed in the Discord.",

   Countdown = 60,

   Accept = function()
   win.NewNotification({
   Title = "RideHub",
   Body = "Thank you for accepting the TOS, enjoy using RideHub!",
   Time = 10
})
   end,

   Reject = function()
   game.Players.LocalPlayer:Kick("You have disagreed to the TOS.")
   end
})
function checkRh()
   for _,v in ipairs(game:GetService("Players"):GetPlayers()) do
       if v.Character.RagdollConstraints:FindFirstChildWhichIsA("HingeConstraint") then return
   else
       win.NewNotification({
           Title = "RideHub",
           Body = "A ReaperHub Buyer was found in your server, " .. v.Name,
           Time = 10
       })
   end
   end
end

checkRh()
local Page = win.NewPage({Text = "Player"})

local Section = Page.NewSection({Text = "Main Player Options."})

local TextBox = Section.NewTextBox({
   Text = "WalkSpeed",
   PlaceHolderText = "",
   Callback = function(text)
       win.NewNotification({
           Title = "RideHub",
           Body = "This is patched, we are working on it.",
           Time = 5
       })
   task.wait()
       local speed = text
       task.wait()
   down = false
   velocity = Instance.new("BodyVelocity")
   velocity.maxForce = Vector3.new(100000, 0, 100000)
   local speed = text
   task.wait()
   gyro = Instance.new("BodyGyro")
   gyro.maxTorque = Vector3.new(100000, 0, 100000)

   local hum = game.Players.LocalPlayer.Character.Humanoid

   function onButton1Down(mouse)
       down = true
       velocity.Parent = game.Players.LocalPlayer.Character.UpperTorso
       velocity.velocity = (hum.MoveDirection) * speed
       gyro.Parent = game.Players.LocalPlayer.Character.UpperTorso
       while down do
           if not down then break end
           velocity.velocity = (hum.MoveDirection) * speed
           local refpos = gyro.Parent.Position + (gyro.Parent.Position - workspace.CurrentCamera.CoordinateFrame.p).unit * 5
           gyro.cframe = CFrame.new(gyro.Parent.Position, Vector3.new(refpos.x, gyro.Parent.Position.y, refpos.z))
           wait(0.1)
       end
   end

   function onButton1Up(mouse)
       velocity.Parent = nil
       gyro.Parent = nil
       down = false
   end
   function onSelected(mouse)
       mouse.KeyDown:connect(function(k) if k:lower()=="q"then onButton1Down(mouse)end end)
       mouse.KeyUp:connect(function(k) if k:lower()=="q"then onButton1Up(mouse)end end)
   end
   onSelected(game.Players.LocalPlayer:GetMouse())
   end,

   Default = "",
   Description = "Type the value here.",

   OnlyNumeric = true,
})
local TextBox = Section.NewTextBox({
   Text = "JumpPower",
   PlaceHolderText = "",
   Callback = function(text)
game.Players.LocalPlayer.Character.Humanoid.JumpPower = text
   end,

   Default = "",
   Description = "Type the value here.",

   OnlyNumeric = true,
})
local Button = Section.NewButton({
   Text = "Player Fly",
   Callback = function()
        repeat wait()
until game.Players.LocalPlayer and game.Players.LocalPlayer.Character and game.Players.LocalPlayer.Character:findFirstChild("Head") and game.Players.LocalPlayer.Character:findFirstChild("Humanoid")
local mouse = game.Players.LocalPlayer:GetMouse()
repeat wait() until mouse
local plr = game.Players.LocalPlayer
local torso = plr.Character.Head
local flying = false
local deb = true
local ctrl = {f = 0, b = 0, l = 0, r = 0}
local lastctrl = {f = 0, b = 0, l = 0, r = 0}
local maxspeed = 400
local speed = 5000

function Fly()
local bg = Instance.new("BodyGyro", torso)
bg.P = 9e4
bg.maxTorque = Vector3.new(9e9, 9e9, 9e9)
bg.cframe = torso.CFrame
local bv = Instance.new("BodyVelocity", torso)
bv.velocity = Vector3.new(0,0.1,0)
bv.maxForce = Vector3.new(9e9, 9e9, 9e9)
repeat wait()
plr.Character.Humanoid.PlatformStand = true
if ctrl.l + ctrl.r ~= 0 or ctrl.f + ctrl.b ~= 0 then
speed = speed+.5+(speed/maxspeed)
if speed > maxspeed then
speed = maxspeed
end
elseif not (ctrl.l + ctrl.r ~= 0 or ctrl.f + ctrl.b ~= 0) and speed ~= 0 then
speed = speed-1
if speed < 0 then
speed = 0
end
end
if (ctrl.l + ctrl.r) ~= 0 or (ctrl.f + ctrl.b) ~= 0 then
bv.velocity = ((game.Workspace.CurrentCamera.CoordinateFrame.lookVector * (ctrl.f+ctrl.b)) + ((game.Workspace.CurrentCamera.CoordinateFrame * CFrame.new(ctrl.l+ctrl.r,(ctrl.f+ctrl.b)*.2,0).p) - game.Workspace.CurrentCamera.CoordinateFrame.p))*speed
lastctrl = {f = ctrl.f, b = ctrl.b, l = ctrl.l, r = ctrl.r}
elseif (ctrl.l + ctrl.r) == 0 and (ctrl.f + ctrl.b) == 0 and speed ~= 0 then
bv.velocity = ((game.Workspace.CurrentCamera.CoordinateFrame.lookVector * (lastctrl.f+lastctrl.b)) + ((game.Workspace.CurrentCamera.CoordinateFrame * CFrame.new(lastctrl.l+lastctrl.r,(lastctrl.f+lastctrl.b)*.2,0).p) - game.Workspace.CurrentCamera.CoordinateFrame.p))*speed
else
bv.velocity = Vector3.new(0,0.1,0)
end
bg.cframe = game.Workspace.CurrentCamera.CoordinateFrame * CFrame.Angles(-math.rad((ctrl.f+ctrl.b)*50*speed/maxspeed),0,0)
until not flying
ctrl = {f = 0, b = 0, l = 0, r = 0}
lastctrl = {f = 0, b = 0, l = 0, r = 0}
speed = 70
bg:Destroy()
bv:Destroy()
plr.Character.Humanoid.PlatformStand = false
end
mouse.KeyDown:connect(function(key)
if key:lower() == "v" then
if flying then flying = false
else
flying = true
Fly()
end
elseif key:lower() == "w" then
ctrl.f = .6
elseif key:lower() == "s" then
ctrl.b = -.6
elseif key:lower() == "a" then
ctrl.l = -.6
elseif key:lower() == "d" then
ctrl.r = .6
end
end)
mouse.KeyUp:connect(function(key)
if key:lower() == "w" then
ctrl.f = 0
elseif key:lower() == "s" then
ctrl.b = 0
elseif key:lower() == "a" then
ctrl.l = 0
elseif key:lower() == "d" then
ctrl.r = 0
end
end)
Fly()
   win.NewNotification({
   Title = "RideHub",
   Body = "V to toggle flight on and off.",
   Time = 5
})
   end,
   Description = "This can be used to fly around."
})
local Button = Section.NewButton({
   Text = "Infinite Stamina",
   Callback = function()
       game:GetService"RunService".RenderStepped:Connect(function()
           game.Players.LocalPlayer.Valuestats.Stamina.Value = 100
       end)
   end,
   Description = "This can be used to run infinitely."
})
local Button = Section.NewButton({
   Text = "Ticket Remover",
   Callback = function()
       if game:GetService("Players").LocalPlayer.PlayerGui:FindFirstChild("Ticket") then
game:GetService("Players").LocalPlayer.PlayerGui:FindFirstChild("Ticket"):Destroy()
       end
   end,
   Description = "This can be used to run infinitely."
})
local Button = Section.NewButton({
   Text = "Infinite Hunger",
   Callback = function()
       game:GetService"RunService".RenderStepped:Connect(function()
           game.Players.LocalPlayer.Valuestats.Hunger.Value = 100
       end)
   end,
   Description = "This can be used to never starve."
})
local Button = Section.NewButton({
   Text = "No Camera Bob",
   Callback = function()
       game:GetService"RunService".RenderStepped:Connect(function()
           game.Players.LocalPlayer.PlayerGui.Camera_Bob.bobbing_global_scale.Value = 0
       end)
   end,
   Description = "This can be used to remove the annoying camera shaking effect."
})
local Button = Section.NewButton({
   Text = "BTools",
   Callback = function()
       local tool1 = Instance.new("HopperBin",game.Players.LocalPlayer.Backpack)
       tool1.BinType = "Hammer"
   end,
   Description = "This can be used to destroy objects."
})
local Button = Section.NewButton({
   Text = "Infinite Jump",
   Callback = function()
       local InfiniteJumpEnabled = true
       game:GetService("UserInputService").JumpRequest:connect(function()
           if InfiniteJumpEnabled then
               game:GetService"Players".LocalPlayer.Character:FindFirstChildOfClass'Humanoid':ChangeState("Jumping")
           end
       end)
   end,
   Description = "This can be used to jump infinitely."
})

local Page2 = win.NewPage({Text = "Game"})

local Section2 = Page2.NewSection({Text = "Main Game Options."})
local TextBox = Section.NewTextBox({
    
   Text = "Teleport to Player",
   PlaceHolderText = "",
   Callback = function(text)
for i,v in pairs(game.Players:GetChildren()) do
if (string.sub(string.lower(v.Name),1,string.len(text))) == string.lower(text) then
text = v.Name
end
end
       local p1 = game.Players.LocalPlayer.Character.HumanoidRootPart
       local p2 = text
       local pos = p1.CFrame
   
       p1.CFrame = game.Players[p2].Character.HumanoidRootPart.CFrame
   end,

   Default = "Player",
   Description = "Type the player's name here.",

   OnlyNumeric = false,
})
local TextBox = Section2.NewTextBox({
   Text = "CBring Player",
   PlaceHolderText = "",
   Callback = function(text)
for i,v in pairs(game.Players:GetChildren()) do
   if (string.sub(string.lower(v.Name),1,string.len(text))) == string.lower(text) then
   text = v.Name
   end
end
local name = text
function cbringTarget()
   repeat
       task.wait()
    game.Players[name].Character.HumanoidRootPart.CFrame = CFrame.new(game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame.Position + game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame.lookVector * 3.6)
    until game.Players[name].Character.Humanoid.Health == 0
end

cbringTarget()

   end,

   Default = "Player",
   Description = "Type the player's name here.",

   OnlyNumeric = false,
})
local TextBox = Section2.NewTextBox({
   Text = "View Player",
   PlaceHolderText = "",
   Callback = function(text)
for i,v in pairs(game.Players:GetChildren()) do
if (string.sub(string.lower(v.Name),1,string.len(text))) == string.lower(text) then
text = v.Name
end
end
game.Workspace.CurrentCamera.CameraSubject = game.Players[text].Character
task.wait(15)
game.Workspace.CurrentCamera.CameraSubject = game.Players.LocalPlayer.Character
   end,

   Default = "Player",
   Description = "Type the player's name here.",

   OnlyNumeric = false,
})
local Button = Section2.NewButton({
   Text = "Building Bypass",
   Callback = function()
       game.ReplicatedStorage.Places.Parent = game.Workspace
   end,
   Description = "Render all interiors at once, (useful)."
})
local Button = Section2.NewButton({
   Text = "Infinite Car Gas",
   Callback = function()
       game:GetService"RunService".RenderStepped:Connect(function()
           game.Players.LocalPlayer.Valuestats.CarGas.Value = 100
       end)
   end,
   Description = "Drive your car endlessly"
})
local Button = Section2.NewButton({
   Text = "Quick Buy Food",
   Callback = function()
       local args = {
           [1] = "Fridge"
       }
       
       game:GetService("ReplicatedStorage").gorillaservice:FireServer(unpack(args))
   end,
   Description = "Buy food quickly."
})
local Button = Section2.NewButton({
   Text = "XP Farm",
   Callback = function()
local CoreGui = game:GetService("StarterGui")

function xpFarm()
   local GC = getconnections or get_signal_cons
   if GC then
       for i,v in pairs(GC(game:GetService("Players").LocalPlayer.Idled)) do
           if v["Disable"] then
               v["Disable"](v)
           elseif v["Disconnect"] then
               v["Disconnect"](v)
           end
       end
   end
   
game:GetService("RunService").Stepped:Connect(function()
game:GetService("Players").LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-425.214722, 68.4271393, 590.490295, 0.526686668, 7.59660992e-08, 0.850059509, 2.90774294e-09, 1, -9.11672302e-08, -0.850059509, 5.04883175e-08, 0.526686668)
end)
end
   xpFarm()
   end,
   Description = "Get your level up not your funny up."
})
local Button = Section2.NewButton({
   Text = "Anti AFK",
   Callback = function()
       local vu = game:GetService("VirtualUser")
       game:GetService("Players").LocalPlayer.Idled:connect(function()
          vu:Button2Down(Vector2.new(0,0),workspace.CurrentCamera.CFrame)
          wait(1)
          vu:Button2Up(Vector2.new(0,0),workspace.CurrentCamera.CFrame)
      end)
   end,
   Description = "Anti AFK."
})
local TextBox = Section2.NewTextBox({
   Text = "FOV",
   PlaceHolderText = "",
   Callback = function(text)
       while task.wait() do
game.Workspace.CurrentCamera.FieldOfView = text
       end
   end,

   Default = "",
   Description = "Your custom FOV here.",

   OnlyNumeric = true,
})

local Button = Section2.NewButton({
   Text = "Silent Aim",
   Callback = function()
       local Config = {
           Enabled = true,
           TeamCheck = false,
           HitPart = "Head",
           Method = "Raycast",
           FieldOfView = {
               Enabled = true,
               Radius = 180
           }
       }
       
       local ExpectedArguments = {
           FindPartOnRayWithIgnoreList = {
               ArgCountRequired = 3,
               Args = {
                   "Instance", "Ray", "table", "boolean", "boolean"
               }
           },
           FindPartOnRayWithWhitelist = {
               ArgCountRequired = 3,
               Args = {
                   "Instance", "Ray", "table", "boolean"
               }
           },
           FindPartOnRay = {
               ArgCountRequired = 2,
               Args = {
                   "Instance", "Ray", "Instance", "boolean", "boolean"
               }
           },
           Raycast = {
               ArgCountRequired = 3,
               Args = {
                   "Instance", "Vector3", "Vector3", "RaycastParams"
               }
           }
       }
       
       local Camera = workspace.CurrentCamera
       local Players = game:GetService("Players")
       
       local LocalPlayer = Players.LocalPlayer
       local Mouse = LocalPlayer:GetMouse()
       
       local GetChildren = game.GetChildren
       local WorldToScreen = Camera.WorldToScreenPoint
       local FindFirstChild = game.FindFirstChild
       
       local function getPositionOnScreen(Vector)
           local Vec3, OnScreen = WorldToScreen(Camera, Vector)
           return Vector2.new(Vec3.X, Vec3.Y), OnScreen
       end
       
       local function ValidateArguments(Args, RayMethod)
           local Matches = 0
           if #Args < RayMethod.ArgCountRequired then
               return false
           end
           for Pos, Argument in next, Args do
               if typeof(Argument) == RayMethod.Args[Pos] then
                   Matches = Matches + 1
               end
           end
           return Matches >= RayMethod.ArgCountRequired
       end
       
       local function getDirection(Origin, Position)
           return (Position - Origin).Unit * 1000
       end
       
       local function getMousePosition()
           return Vector2.new(Mouse.X, Mouse.Y)
       end
       
       local function getClosestPlayer()
           if not Config.HitPart then return end
           local Closest
           local DistanceToMouse
           for _, Player in next, GetChildren(Players) do
               if Player == LocalPlayer then continue end
               if Config.TeamCheck and Player.Team == LocalPlayer.Team then continue end
       
               local Character = Player.Character
       
               if not Character then continue end
       
               local HumanoidRootPart = FindFirstChild(Character, "HumanoidRootPart")
               local Humanoid = FindFirstChild(Character, "Humanoid")
       
               if not HumanoidRootPart or not Humanoid or Humanoid and Humanoid.Health <= 0 then continue end
       
               local ScreenPosition, OnScreen = getPositionOnScreen(HumanoidRootPart.Position)
       
               if not OnScreen then continue end
       
               local Distance = (getMousePosition() - ScreenPosition).Magnitude
               if Distance <= (DistanceToMouse or (Config.FieldOfView.Enabled and Config.FieldOfView.Radius) or 2000) then
                   Closest = Character[Config.HitPart]
                   DistanceToMouse = Distance
               end
           end
           return Closest
       end
       
       local oldNamecall
       oldNamecall = hookmetamethod(game, "__namecall", function(...)
           local Method = getnamecallmethod()
           local Arguments = {...}
           local self = Arguments[1]
       
           if Config.Enabled and self == workspace then
               if Method == "FindPartOnRayWithIgnoreList" and Config.Method == Method then
                   if ValidateArguments(Arguments, ExpectedArguments.FindPartOnRayWithIgnoreList) then
                       local A_Ray = Arguments[2]
       
                       local HitPart = getClosestPlayer()
                       if HitPart then
                           local Origin = A_Ray.Origin
                           local Direction = getDirection(Origin, HitPart.Position)
                           Arguments[2] = Ray.new(Origin, Direction)
       
                           return oldNamecall(unpack(Arguments))
                       end
                   end
               elseif Method == "FindPartOnRayWithWhitelist" and Config.Method == Method then
                   if ValidateArguments(Arguments, ExpectedArguments.FindPartOnRayWithWhitelist) then
                       local A_Ray = Arguments[2]
       
                       local HitPart = getClosestPlayer()
                       if HitPart then
                           local Origin = A_Ray.Origin
                           local Direction = getDirection(Origin, HitPart.Position)
                           Arguments[2] = Ray.new(Origin, Direction)
       
                           return oldNamecall(unpack(Arguments))
                       end
                   end
               elseif (Method == "FindPartOnRay" or Method == "findPartOnRay") and Config.Method:lower() == Method:lower() then
                   if ValidateArguments(Arguments, ExpectedArguments.FindPartOnRay) then
                       local A_Ray = Arguments[2]
       
                       local HitPart = getClosestPlayer()
                       if HitPart then
                           local Origin = A_Ray.Origin
                           local Direction = getDirection(Origin, HitPart.Position)
                           Arguments[2] = Ray.new(Origin, Direction)
       
                           return oldNamecall(unpack(Arguments))
                       end
                   end
               elseif Method == "Raycast" and Config.Method == Method then
                   if ValidateArguments(Arguments, ExpectedArguments.Raycast) then
                       local A_Origin = Arguments[2]
       
                       local HitPart = getClosestPlayer()
                       if HitPart then
                           Arguments[3] = getDirection(A_Origin, HitPart.Position)
       
                           return oldNamecall(unpack(Arguments))
                       end
                   end
               end
           end
           return oldNamecall(...)
       end)
   end,
   Description = "This can be used to give a great advantage in gun fights."
})
local Button = Section2.NewButton({
   Text = "Aimbot",
   Callback = function()
getgenv().AimPart = "Head" -- For R15 Games: {UpperTorso, LowerTorso, HumanoidRootPart, Head} | For R6 Games: {Head, Torso, HumanoidRootPart}
getgenv().AimlockToggleKey = "L" -- Toggles Aimbot On/Off 
getgenv().AimRadius = 50 -- How far away from someones character you want to lock on at
getgenv().ThirdPerson = false -- Locking onto someone in your Third Person POV
getgenv().FirstPerson = true -- Locking onto someone in your First Person POV
getgenv().TeamCheck = false -- Check if Target is on your Team (True means it wont lock onto your teamates, false is vice versa) (Set it to false if there are no teams)
getgenv().PredictMovement = false -- Predicts if they are moving in fast velocity (like jumping) so the aimbot will go a bit faster to match their speed 
getgenv().PredictionVelocity = 10 -- The speed of the PredictMovement feature 

loadstring(game:HttpGet("https://raw.githubusercontent.com/Exhalez/snadkoas/main/black.lua", true))()
end,
   Description = "This can be used to give a great advantage in gun fights, to activate press L"
})
local Button = Section2.NewButton({
   Text = "Pickup Tools",
   Callback = function()
local g = game.Workspace.tools

for fk, fl in pairs((g:GetChildren())) do
   if fl:IsA("Tool") and fl.Name == "Fist" and fl.Name ~= "Phone" and fl.Name ~= "Crate" then
       game:GetService("Players").LocalPlayer.Character.Humanoid:EquipTool(fl)
       break
   end
end
   end,
   Description = "This can be used to pickup all tools."
})
local Button = Section2.NewButton({
   Text = "Infinite Skittles",
   Callback = function()
       pcall(function()
           while wait() do
               game:GetService("Players").LocalPlayer.PlayerGui.Run.Value.Value = true
               game.Players.LocalPlayer.Character.Resistance.Value = true
               game:GetService("Workspace").LocalPlayer.Resistance = true
           end
       end)  
   end,
   Description = "This can be used to simulate the effect of skittles."
})
local Button = Section2.NewButton({
   Text = "Anti Camera Bob",
   Callback = function()
       repeat
           wait()
   if game:GetService("Players").LocalPlayer.PlayerGui:FindFirstChild("Camera_Bob") then
       game:GetService("Players").LocalPlayer.PlayerGui:FindFirstChild("Camera_Bob"):Destroy()
   end
   until not game:GetService("Players").LocalPlayer.PlayerGui:FindFirstChild("Camera_Bob")
   end,
   Description = "This can be used to remove the annoying camera shake whilst running."
})
local TextBox = Section2.NewTextBox({
   Text = "Custom Date",
   PlaceHolderText = "",
   Callback = function(text)
       game:GetService("Players").LocalPlayer.PlayerGui.Stats.TextLabel.Text = text
       game:GetService("Players").LocalPlayer.PlayerGui.Stats.TextLabel.LocalScript:Destroy()
   end,

   Default = "",
   Description = "Type the name that you want here.",

   OnlyNumeric = false,
})
local TextBox = Section2.NewTextBox({
   Text = "Custom Time",
   PlaceHolderText = "",
   Callback = function(text)
       game.Players.LocalPlayer.PlayerGui.Stats.Time.LocalScript:Destroy()
       game:GetService("Players").LocalPlayer.PlayerGui.Stats.Time.Text = text
   end,

   Default = "",
   Description = "Type the time that you want here.",

   OnlyNumeric = true,
})

local Button = Section2.NewButton({
   Text = "Anti Combat Log",
   Callback = function()
       game:GetService("Players").LocalPlayer.PlayerGui.Stats.CLog:Destroy()
   end,
   Description = "This can be used to remove the annoying combat log system."
})
local Button = Section2.NewButton({
   Text = "Anti Blur",
   Callback = function()
       while wait() do
           for fd, fe in pairs(game:GetService("Workspace").Camera:GetChildren()) do
             fe:Destroy()
           end
     end
     if game:GetService("Players").LocalPlayer.PlayerGui.Dmg then
       game:GetService("Players").LocalPlayer.PlayerGui.Dmg:Destroy()
       end
   end,
   Description = "This can be used to remove the annoying ass blur."
})
local Button = Section2.NewButton({
   Text = "Anti Ragdoll",
   Callback = function()
       game:GetService("RunService").Stepped:Connect(function()
           if game:GetService("Players").LocalPlayer.Character.Head.EDead then
               game:GetService("Players").LocalPlayer.Character.Head.EDead:Destroy()
   game.Players.LocalPlayer.Character:FindFirstChild("Ragdoller"):Destroy()
   game.Players.LocalPlayer.Character:FindFirstChild("HurtSystem"):Destroy()
   end
   end)
   end,
   Description = "This can be used to remove ragdolling."
})
local Section3 = Page2.NewSection({Text = "Combat"})
local Button = Section3.NewButton({
   Text = "Infinite Ammo",
   Callback = function()
local oldK; oldK = hookmetamethod(game, "__namecall", newcclosure(function(self, ...)
   args = {...}
   if tostring(self) == "Fire" and args[2] == true then
       args[2] = false
       return oldK(self, unpack(args))
   end
   return oldK(self, ...)
end))
   end,
   Description = "This can be used to shoot infinitely, yurr hear?"
})
local Button = Section3.NewButton({
   Text = "Fire Rate",
   Callback = function()
local old = nil

for i, v in pairs(game.Players.LocalPlayer.Character:GetChildren()) do
if v.ClassName == "Tool" and v:FindFirstChild("Pistol") then
   old = v
end
end
local new = getsenv(old:FindFirstChild("Pistol"))
local hookOld = function(number)
debug.setconstant(new.OnFire, 70, number)
end

       local script = nil

       for i, v in pairs(game.Players.LocalPlayer.Character:GetChildren()) do
           if v.ClassName == "Tool" then
               script = v
           end
       end
       
       local senv = getsenv(script)
       local constant = debug.getconstant(senv.OnFire, 15)
       debug.setconstant(senv.OnFire, 15, -1)
   end,
   Description = "This can be used to shoot bullets faster."
})
local Button = Section3.NewButton({
   Text = "Anti Recoil",
   Callback = function()
       local gun = nil

       for i, v in pairs(game.Players.LocalPlayer.Character:GetChildren()) do
           if v.ClassName == "Tool" then
               print(v.Name .. "Was Found")
               gun = v
           end
       end
       
       
       local get = gun:FindFirstChild("Pistol")
       get.Parent.Recoil.AnimationId = "rbxassetid://1234567"
       
       local hook
       hook = hookfunction(getrenv().delay, newcclosure(function(...)
           local args = {...}
           local caller = getcallingscript()
           
           if caller == get then
               if typeof(args[2]) == "function" then
                   args[2] = function()
                       print("hooked")
                   end
               end
           end
           return hook(table.unpack(args))
       end))
   end,
   Description = "This can be used to shoot without the annoying gun recoil."
})
local Button = Section3.NewButton({
   Text = "One Shot",
   Callback = function()
local settings = {repeatamount = 20}
local mt = getrawmetatable(game)
local old = mt.__namecall

setreadonly(mt, false)

task.spawn(function()
mt.__namecall = function(self, ...)
  local args = {...}
  local method = getnamecallmethod();
  if method == "FireServer" and self.Name == "Impact" then
      for i = 1, settings.repeatamount do
          old(self, ...)
      end;
  end;
  return old(self, ...)
end
end)
setreadonly(mt, true)
   end,
   Description = "This can be used to make your gun kill anyone in one shot."
})
local Button = Section3.NewButton({
   Text = "Hitbox Expander",
   Callback = function()
       function getplrsname()
           for i,v in pairs(game:GetChildren()) do
               if v.ClassName == "Players" then
                   return v.Name
               end
           end
       end
       local players = getplrsname()
       local plr = game[players].LocalPlayer

       while  wait(1) do
           coroutine.resume(coroutine.create(function()
               for _,v in pairs(game[players]:GetPlayers()) do
                   if v.Name ~= plr.Name and v.Character then
                       v.Character.Head.CanCollide = false
                       v.Character.Head.Material = "Plastic"
                       v.Character.Head.Transparency = 0.4
                       v.Character.Head.Size = Vector3.new(4.1,4.1,4.1)
                   end
               end
           end))
       end
   end,
   Description = "This can be used as an alternative to Silent Aim (seems more legit)"
})
local Button = Section3.NewButton({
   Text = "CornerBox ESP",
       Callback = function()
           loadstring(game:HttpGet("https://raw.githubusercontent.com/Exhalez/snadkoas/main/CornerBox%20ESP%20Rainbow"))()
   Description = "See anyone from in the map, anywhere. sussy ESP!"
end
})
local Button = Section3.NewButton({
   Text = "Name ESP",
       Callback = function()
           loadstring(game:HttpGet("https://raw.githubusercontent.com/Exhalez/snadkoas/main/Name%20ESP"))()
   Description = "See anyone from in the map, anywhere. sussy ESP!"
end
})
   local Button = Section3.NewButton({
   Text = "Body ESP (White)",
       Callback = function()
           loadstring(game:HttpGet("https://raw.githubusercontent.com/Exhalez/snadkoas/main/ESP"))()
   Description = "See anyone from in the map, anywhere. sussy ESP!"
end
})
local Button = Section3.NewButton({
   Text = "Click TP (CTRL)",
   Callback = function()
       function clickTP()
           local plr = game.Players.LocalPlayer
           local ms = plr:GetMouse()
           
           ms.Button1Down:Connect(function()
               if not
               game.UserInputService:IsKeyDown(Enum.KeyCode.LeftControl) then return end
               if not ms.Target then return end
               plr.Character:MoveTo(ms.Hit.p)
           end)
       end
       clickTP()      
   end,
   Description = "This can be used to teleport wherever you click whilst holding Left Control."
})
local Button = Section3.NewButton({
   Text = "Dupe Tool",
   Callback = function()
       rconsoleprint("Equip the tool and left click to crash your game, then go to the SL2 server list and join a new server, don't leave the current one or it'll fuck up.")
       Tool = Instance.new("Tool")
       Tool.RequiresHandle = false
       Tool.Name = "DupeTool"
       
        Tool.Activated:connect(function()
           while (true) do end
        end)
       
        Tool.Parent = game.Players.LocalPlayer.Backpack
   end,
   Description = "This can be used to dupe items."
})

local Toggle = Section3.NewToggle({
   Text = "Push Aura",
   Callback = function(bool)
       _G.Push = bool
       while _G.Push == true do
           wait()
           local char = game.Players.LocalPlayer.Character
           if char and char:FindFirstChild("Fist") then
               local Event = char.Fist.LocalScript.Script.legma
               Event:FireServer()
               for i,v in pairs(game:GetService("Players"):GetPlayers()) do
                   if v ~= game.Players.LocalPlayer then
                       local all = v
                       local Event = char.Fist.LocalScript.p
                       Event:FireServer(all)
                   end
               end
           end
       end
   end,
   Default = false,
   Description = "This can be used to push anyone near you."
})

local Page3 = win.NewPage({Text = "Misc"})

local Section4 = Page3.NewSection({Text = "Main Misc Options."})
local Button = Section4.NewButton({
   Text = "Faceless",
   Callback = function()
       game.Players.LocalPlayer.Character.Head:FindFirstChild("Sad"):Destroy()
       game.Players.LocalPlayer.Character.Head:FindFirstChild("Stare"):Destroy()
       game.Players.LocalPlayer.Character.Head:FindFirstChild("Mad"):Destroy()
   end,
   Description = "This can be used to look cool."
})
local Button = Section4.NewButton({
   Text = "No Name",
   Callback = function()
       if game:GetService("Players").LocalPlayer.Character.Head.Gui then
           game:GetService("Players").LocalPlayer.Character.Head.Gui:Destroy()
       end
   end,
   Description = "This can be used to look cool. "
})
local Button = Section4.NewButton({
   Text = "No Legs",
   Callback = function()
       game:GetService("Players").LocalPlayer.Character.LeftUpperLeg:Destroy()
       game:GetService("Players").LocalPlayer.Character.LeftLowerLeg:Destroy()
       game:GetService("Players").LocalPlayer.Character.RightUpperLeg:Destroy()
       game:GetService("Players").LocalPlayer.Character.RightLowerLeg:Destroy()
   end,
   Description = "This can be used to look cool. "
})
local Button = Section4.NewButton({
   Text = "No Arms",
   Callback = function()
       game:GetService("Players").LocalPlayer.Character.RightUpperArm:Destroy()
       game:GetService("Players").LocalPlayer.Character.RightLowerArm:Destroy()
       game:GetService("Players").LocalPlayer.Character.LeftUpperArm:Destroy()
       game:GetService("Players").LocalPlayer.Character.LeftLowerArm:Destroy()
   end,
   Description = "This can be used to look cool. "
})
local Button = Section4.NewButton({
   Text = "Fake Korblox",
   Callback = function()
       game:GetService("Players").LocalPlayer.Character.LeftUpperLeg:Destroy()
       game:GetService("Players").LocalPlayer.Character.LeftLowerLeg:Destroy()
   end,
   Description = "This can be used to look cool. "
})
local Button = Section4.NewButton({
   Text = "No Head",
   Callback = function()
       game.Players.LocalPlayer.Character.Head.Neck:Destroy()
game.Players.LocalPlayer.Character.UpperTorso.NeckAttachment:Destroy()
game.Players.LocalPlayer.Character.Humanoid.HealthDisplayDistance = math.huge
game.Players.LocalPlayer.Character.Humanoid.NameDisplayDistance = math.huge
game.Players.LocalPlayer.Character.Head.Size = Vector3.new(0, 0, 0)
game.Players.LocalPlayer.Character.Head.Massless = true
game.Players.LocalPlayer.Character.Head.CanCollide = false
heazd = true
         while heazd == true do
           pcall(function()
             game.Players.LocalPlayer.Character.Head.NeckRigAttachment.CFrame = CFrame.new(0, 100000,473632813, 0)
             game.Players.LocalPlayer.Character.UpperTorso.NeckRigAttachment.CFrame = CFrame.new(0, 100000,473632813, 0)
             game.Players.LocalPlayer.Character.Head.CFrame = CFrame.new(0, 100000,473632813, 0)
           end)
           wait()
         end
   end,
   Description = "This can be used to look cool. "
})
local Button = Section4.NewButton({
   Text = "Blocky Head",
   Callback = function()
       function heady()
           pcall(function()
          game.Players.LocalPlayer.Character.Head.Mesh:Destroy()
          game.Players.LocalPlayer.Character.Head.ear2.Mesh:Destroy()
          game.Players.LocalPlayer.Character.Head.ear.Mesh:Destroy()
          end)
       end
       heady()
   end,
   Description = "This can be used to look weird."
})
local Button = Section4.NewButton({
   Text = "Celebrity Tag",
   Callback = function()
       game:GetService("Players").LocalPlayer.Character.Head.Gui.MainFrame.Celeb.Visible = true
   end,
   Description = "This can be used to look weird."
})
local Button = Section4.NewButton({
   Text = "Jump Cooldown Bypass",
   Callback = function()
       game:GetService("Players").LocalPlayer.PlayerGui.JumpCooldown:Destroy()
   end,
   Description = "This can be used to look cool. "
})
local Section5 = Page3.NewSection({Text = "More Misc Options."})
local TextBox = Section5.NewTextBox({
   Text = "Change RP Name",
   PlaceHolderText = "",
   Callback = function(text)
       game.Players.LocalPlayer.Character.Head.Gui.MainFrame.NameLabel.Text = text
   end,

   Default = "",
   Description = "Change RP Name",

   OnlyNumeric = false,
})
local TextBox = Section5.NewTextBox({
   Text = "Change RP Level",
   PlaceHolderText = "",
   Callback = function(text)
       game.Players.LocalPlayer.Character.Head.Gui.MainFrame.Age.Text = text
   end,

   Default = "",
   Description = "Change RP Level.",

   OnlyNumeric = true,
})
local TextBox = Section5.NewTextBox({
   Text = "Change RP Rank",
   PlaceHolderText = "",
   Callback = function(text)
       game.Players.LocalPlayer.Character.Head.Gui.MainFrame.Rank.Text = text
   end,

   Default = "",
   Description = "Change RP Rank.",

   OnlyNumeric = true,      

})
 local TextBox = Section5.NewTextBox({
    Text = "Send 10k",
    PlaceHolderText = "",
    Callback = function(text)
        for i,v in pairs(game.Players:GetChildren()) do
if (string.sub(string.lower(v.Name),1,string.len(text))) == string.lower(text) then
text = v.Name
end
end
    
    local A_1 = "10000"
    local A_2 = game.Players[text]
    local Event = game:GetService("ReplicatedStorage").Send
    Event:FireServer(A_1, A_2)
        
        end,
    Default = "",
    Description = "You have sent 10k cash to the player, enjoy!.",

    OnlyNumeric = false,
 })
 
local Button = Section5.NewButton({
   Text = "Iced Out Tag",
   Callback = function()
       game.Players.LocalPlayer.Character.Head.Gui.MainFrame.IceD.Visible = true
   end,
   Description = "Iced out tag."
})
local Button = Section5.NewButton({
   Text = "Safe Mode",
   Callback = function()
       local tp = game.Players.LocalPlayer.Character.HumanoidRootPart

   local on = true
   while on do
       task.wait(0.1)
       if game.Players.LocalPlayer.Character.Humanoid.Health > 70 then
       elseif game.Players.LocalPlayer.Character.Humanoid.Health <= 70 then
           local startpos1 = game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame.Position
           repeat
               wait(0.05)
               game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-146.748886, 3.85716486, 1330.50427, 0.989451289, 1.18913936e-08, 0.144866109, -1.3166213e-08, 1, 7.84125653e-09, -0.144866109, -9.66587876e-09, 0.989451289)
           until game.Players.LocalPlayer.Character.Humanoid.Health > 70
           game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(startpos1)
       end
   end

   end,
   Description = "Quickly Regenerate Health."
})
local Button = Section5.NewButton({
   Text = "Reset",
   Callback = function()
       game.Players.LocalPlayer.Character.Humanoid.Health = 0
   end,
   Description = "Quickly Reset"
})
local TextBox = Section5.NewTextBox({
   Text = "Car Speed",
   PlaceHolderText = "",
   Callback = function(text)
local cMod = require(game:GetService("Workspace")[game.Players.LocalPlayer.Name.."'s Car"]["A-Chassis Tune"])

cMod["A-Chassis Tune"]["A-Chassis Interface"]["AC6_Stock_Sound"]:Destroy()
cMod["Ashaltacb's Car"]["A-Chassis Tune"]["A-Chassis Interface"]["AC6_Exhaust vibration"]:Destroy()

cMod.LoadDelay = 0
cMod.Weight = 0
cMod.AntiRoll = 100
cMod.SteerSpeed = 0.10
cMod.Horsepower = text
   end,

   Default = "",
   Description = "Change Car Speed.",

   OnlyNumeric = true,
})
local Button = Section5.NewButton({
   Text = "Free Camera",
   Callback = function()
       loadstring(game:HttpGet("https://pastebin.com/raw/mfrMFUcJ"))()
   end,
   Description = "Free Camera."
})
local Button = Section5.NewButton({
   Text = "Bypass Camera Zoom",
   Callback = function()
       game.Players.LocalPlayer.CameraMaxZoomDistance = math.random(999,1337)
   end,
   Description = "Bypass The Camera Zoom."
})
local Button = Section5.NewButton({
   Text = "MET Radio",
   Callback = function()
           game.StarterGui:SetCore("SendNotification", {
       Title = "MET Radio",
       Text = "This will let you have to access the MET radio, doesn't work if there isn't a MET in the game."
   })
   local Target = nil
   for i,v in pairs(game.Players:GetChildren()) do
       if v.TeamColor == BrickColor.new("Navy blue") then
           Target = v.Name
       end
   end
   for i,v in pairs(game.Players[Target].Backpack:GetChildren()) do
       if v.Name == "Radio" then
           v:Clone().Parent = game.Players.LocalPlayer.Backpack
       end
   end
   end,
   Description = "Troll MET using an FE MET Radio."
})
local Button = Section5.NewButton({
   Text = "Rejoin",
   Callback = function()
       local teles = game.TeleportService
       local p = game.Players.LocalPlayer

       teles:Teleport(game.PlaceId, p)
   end,
   Description = "Rejoin The Game."
})

local Page13 = win.NewPage({Text = "Teleportation"})

local Section7 = Page13.NewSection({Text = "Main Teleports."})
local Button = Section7.NewButton({
   Text = "Apartment 1",
   Callback = function()
       game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-176.541977, -457.964905, -69.6778412, 0.0172199383, -7.30185334e-08, 0.999851704, -1.86776674e-08, 1, 7.33510319e-08, -0.999851704, -1.99379979e-08, 0.0172199383)
   end,
   Description = "Teleports to selected building."
})
local Button = Section7.NewButton({
   Text = "Apartment 2",
   Callback = function()
       game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-175.904221, -457.964905, -493.479797, 0.0789805874, -2.37789219e-08, 0.99687618, -4.13485459e-08, 1, 2.71294027e-08, -0.99687618, -4.33620748e-08, 0.0789805874)
   end,
   Description = "Teleports to selected building."
})
local Button = Section7.NewButton({
   Text = "Apartment 3",
   Callback = function()
       game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-0.532082677, -457.913483, -112.602715, -0.000539803877, -4.52883206e-08, -0.999999881, 6.60640032e-09, 1, -4.52918947e-08, 0.999999881, -6.63084831e-09, -0.000539803877)
   end,
   Description = "Teleports to selected building."
})
local Button = Section7.NewButton({
   Text = "Sports Direct",
   Callback = function()
       game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-195.589691, -463.662384, 92.2535934, 0.238895774, 2.38148239e-08, 0.971045196, 3.21983293e-08, 1, -3.24463443e-08, -0.971045196, 3.90173298e-08, 0.238895774)
   end,
   Description = "Teleports to selected building."
})
local Button = Section7.NewButton({
   Text = "Tescos",
   Callback = function()
       game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(983.751831, -446.635803, 103.678848, -0.381174803, -9.88733646e-08, -0.924502969, -2.49378118e-08, 1, -9.66656728e-08, 0.924502969, -1.37914373e-08, -0.381174803)
   end,
   Description = "Teleports to selected building."
})
Button = Section7.NewButton({
   Text = "New London",
   Callback = function()
       game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(612.033203, -400.384491, -106.705254, -0.0193231795, -7.59797825e-09, 0.999813318, 1.18716381e-09, 1, 7.62234187e-09, -0.999813318, 1.33423006e-09, -0.0193231795)
   end,
   Description = "Teleports to selected building."
})
local Button = Section7.NewButton({
   Text = "Ultimate Drip",
   Callback = function()
       game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(479.154602, -395.400482, -91.1273499, 0.216078922, 1.49673074e-08, 0.976375878, -1.26980304e-09, 1, -1.50484354e-08, -0.976375878, 2.01184469e-09, 0.216078922)
   end,
   Description = "Teleports to selected building."
})
local Button = Section7.NewButton({
   Text = "Gun/Melee Dealer",
   Callback = function()
       game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(55.4791451, 4.1782546, -126.901131, 0.997650862, -1.03924357e-07, 0.0685039684, 1.04001337e-07, 1, 2.44261367e-09, -0.0685039684, 4.68762895e-09, 0.997650862)
   end,
   Description = "Teleports to selected building."
})
local Button = Section7.NewButton({
   Text = "Mask/Skittles",
   Callback = function()
       game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-176.336624, -0.500741839, 146.262192, 0.00358911627, 3.95761042e-08, -0.999993563, 3.16052393e-08, 1, 3.96897946e-08, 0.999993563, -3.174749e-08, 0.00358911627)
   end,
   Description = "Teleports to selected building."
})
local Button = Section7.NewButton({
   Text = "Turkish Barber",
   Callback = function()
       game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(223.995895, -347.569946, 874.736816, 0.89640069, 6.32670947e-08, -0.443244576, -2.20718714e-08, 1, 9.8099008e-08, 0.443244576, -7.81527802e-08, 0.89640069)
   end,
   Description = "Teleports to selected building."
})
local Button = Section7.NewButton({
   Text = "Female Barber",
   Callback = function()
       game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-285.492859, -347.569977, 1315.14221, 0.976763368, -4.70047361e-08, -0.214320675, 5.06192883e-08, 1, 1.1377014e-08, 0.214320675, -2.19614105e-08, 0.976763368)
   end,
   Description = "Teleports to selected building."
})
local Button = Section7.NewButton({
   Text = "Urban Farm",
   Callback = function()
       game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-148.975693, -346.269897, 1329.96362, 0.160105869, 1.77326021e-09, 0.987099826, -2.56679095e-10, 1, -1.75480153e-09, -0.987099826, 2.75861348e-11, 0.160105869)
   end,
   Description = "Teleports to selected building."
})
local Button = Section7.NewButton({
   Text = "Tattoo Place",
   Callback = function()
       game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-286.175018, -347.569946, 1316.57288, 0.954570174, 8.2568512e-08, -0.29798618, -8.18485191e-08, 1, 1.48945078e-08, 0.29798618, 1.01718758e-08, 0.954570174)
   end,
   Description = "Teleports to selected building."
})
local Button = Section7.NewButton({
   Text = "Car Dealership",
   Callback = function()
       game.Players.LocalPlayer.Character.HumanoidRootPart.CFrame = CFrame.new(-186.654739, -463.662415, 1174.18298, 0.130901337, 5.79686592e-08, -0.991395414, 5.18117593e-09, 1, 5.91558944e-08, 0.991395414, -1.28801796e-08, 0.130901337)
   end,
   Description = "Teleports to selected building."
})
local Page15 = win.NewPage({Text = "Credits"})

local Section8 = Page15.NewSection({Text = "Creator and God Father + Created Whitelist"})
local Button = Section8.NewButton({
   Text = "ride#0625",
   Callback = function()
      end
})
local Section8 = Page15.NewSection({Text = "The O.G"})
local Button = Section8.NewButton({
   Text = "antikur - W mans",
   Callback = function()
   end
})
local Section8 = Page15.NewSection({Text = "Batty Boy"})
local Button = Section8.NewButton({
   Text = "notfrostedwow - Obfuscation + Some Scripting",
   Callback = function()
      end
})
		print("whitelisted!")
	end
end
