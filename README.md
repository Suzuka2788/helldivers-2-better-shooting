# Suzuka’s Better Shooting v1.0.0

A Helldivers 2 shooting quality-of-life mod. In-game settings share one **Suzuka Better Shooting** tab.

## Features

- Hold Fire to cycle fully charged shots, with individual charged-weapon switches.
- Hold Fire to repeat three-round bursts; adjustable pause between bursts.
- Optional held-fire repeat for eligible semi-auto weapons. Maximum rate factor: **0–1**, step **0.05**. Turning repeat OFF restores manual fire and resets the factor to 1. Charged weapons are excluded.
- Optional APW-1 Anti-Materiel Rifle hip-fire crosshair.
- Optional normal crosshairs for P-4 Senator and LAS-58 Talon.
- Senator: native fixed laser sight. This replaces its selectable flashlight attachment; existing weapon instances must be recreated after installation.
- Talon: default native laser/flashlight attachment.
- Independent **PISTOL STAT BOOST** toggle, default ON: Senator ergonomics **75→85**, Talon **95→105**; both sway multipliers **1→0.85**. OFF restores all three native values. Crosshairs and lasers remain independent. No damage, penetration or magazine boosts.

## Installation

Requires [Bingus Shared Loader API 1](https://github.com/CowboyBingus/BingusSharedLoader) and [Mod Options Menu](https://github.com/CowboyBingus/ModOptionsMenu) for saved in-game settings.

1. Close the game. Import **Suzukas-Better-Shooting-v1.0.0.zip** into your mod manager.
2. Replace older Better Shooting versions and disable separate Charge Auto Cycle, Burst Hold and Senator/Talon packages that duplicate these components.
3. Select the desired installer components. The crosshair, laser and stat-boost settings require the pistol/crosshair component.
4. Deploy and restart. Change settings under **Suzuka Better Shooting**, then select **APPLY**. Re-equip the Senator and enter a new mission to test the new laser attachment.

The package retains the preview GUID and settings identifiers for upgrades. Default crosshair and pistol stat-boost toggles are ON.

## Validation and compatibility

Offline LuaJIT checks cover the charge/burst/semi policies, menu settings, eight crosshair/stat-boost combinations, native laser references, write/readback/restoration and all 16 installer combinations. The fixed Senator laser and complete v1.0.0 combination still require in-game confirmation. A successful memory-write log alone does not prove the attachment is rendered.

The mod validates the supported game build and original component records before writing. Game updates or overlapping record modifications can cause it to refuse writes. This release does not claim compatibility with every weapon-enhancement package.

## Credits and source

Includes locally developed Charge Auto Cycle, Suzuka Burst Hold, semi-auto repeat and pistol/crosshair integration. The APW-1 crosshair fields are reused from Support Recoil Half; its recoil and magazine boosts are not included. Source package hashes are in `components.json` and `crosshair-source.json` inside the download.

The `source/` directory in this repository contains the exact generated Lua entry resources from the release archive. Bingus-related third-party license text is included as `LICENSE-CowboyBingus.txt`.

## 中文说明

统一设置页为 **Suzuka Better Shooting**。包含自动满蓄力循环、按住三连发、可开关的半自动连点及 0–1 射速系数、反器材准星、参议员／猛爪普通准星和镭射。数值强化独立开关为 **PISTOL STAT BOOST**：关闭恢复两把手枪原生操控和晃动数值，不影响准星与镭射。修改设置后点击 **APPLY**。参议员改为固定镭射，不再提供手电切换。已通过离线检查，完整组合及新参议员镭射仍待实机确认。
