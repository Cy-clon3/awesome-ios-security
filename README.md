# Awesome iOS Security [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

[<img src="https://upload.wikimedia.org/wikipedia/commons/5/56/IOS_15_logo.png" align="right" width="70">]()

> [<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/1/1b/Apple_logo_grey.svg/30px-Apple_logo_grey.svg.png" width="16">]() A curated list of awesome iOS application security resources.

A collection of awesome tools, books, courses, blog posts, and cool stuff about iOS Application Security and Penetration Testing.

---

## Contents

- [Tools](#tools)
  - [Reverse Engineering](#reverse-engineering-tools)
  - [Static Analysis](#static-analysis-tools)
  - [Dynamic Analysis](#dynamic-analysis-tools)
- [Frida Scripts](#frida-scripts)
- [Tweaks](#tweaks)
  - [Reverse Engineering Tweaks](#reverse-engineering-tweaks)
  - [Jailbrek Detection Bypass Tweaks](#jailbrek-detection-bypass-tweaks)
  - [SSL Pinning Bypass Tweaks](#ssl-pinning-bypass-tweaks)
- [Courses](#courses)
- [Books](#books)
- [Tutorials](tutorials)
- [Articles](articles)
  - [Penetration Testing Articles](#penetration-testing-articles)
  - [Reverse Engineering Articles](#reverse-engineering-articles)
  - [Jailbrek Detection Bypass Articles](#jailbrek-detection-bypass-articles)
  - [SSL Pinning Bypass Articles](#ssl-pinning-bypass-articles)
- [Checklists & CheatSheets](#checklists-&-CheatSheets)
- [Labs](#labs)
  - [CTF](#ctf)
- [Writeups](#writeups)
- [Misc](#misc)

## Tools

<a name="reverse-engineering-tools"></a>
### Reverse Engineering Tools
- [Hopper](https://www.hopperapp.com/) - A reverse engineering tool that will assist you in your static analysis of executable files.
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) - A software reverse engineering (SRE) framework created and maintained by the National Security Agency Research Directorate.
- [Radare2](https://github.com/radareorg/radare2) - UNIX-like reverse engineering framework and command-line toolset.
- [Cutter](https://github.com/rizinorg/cutter) - Free and Open Source Reverse Engineering Platform powered by rizin.
- [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) - A tool to pull a decrypted IPA from a jailbroken device.
- [bagbak](https://github.com/ChiChou/bagbak) - Yet another frida based App decryptor. Requires jailbroken iOS device and frida.re.
- [flexdecrypt](https://github.com/JohnCoates/flexdecrypt) - iOS App & Mach-O binary decryptor.
- [bfdecrypt](https://github.com/BishopFox/bfdecrypt) - Utility to decrypt App Store apps on jailbroken iOS 11.x.
- [bfinject](https://github.com/BishopFox/bfinject) - Easy dylib injection for jailbroken 64-bit iOS 11.0 - 11.1.2. Compatible with Electra and LiberiOS jailbreaks.
- [r2flutch](https://github.com/as0ler/r2flutch) - Yet another tool to decrypt iOS apps using r2frida.
- [Clutch](https://github.com/KJCracks/Clutch) - A high-speed iOS decryption tool.
- [dsdump](https://github.com/DerekSelander/dsdump) - An improved nm + objc/swift class-dump tool.
- [class-dump](https://github.com/nygard/class-dump) - A command-line utility for examining the Objective-C segment of Mach-O files.
- [SwiftDump](https://github.com/neil-wu/SwiftDump/) - A command-line tool for retriving the Swift Object info from Mach-O file.
- [jtool](http://www.newosxbook.com/tools/jtool.html) - An app inspector, disassembler, and signing utility for the macOS, iOS.
- [Sideloadly](https://sideloadly.io/) - An app to sideload your favorite games and apps to Jailbroken & Non-Jailbroken iOS devices.
- [Cydia Impactor](http://www.cydiaimpactor.com/) - A GUI tool for sideloading iOS application.
- [iOS App Signer](https://github.com/DanTheMan827/ios-app-signer) - an app for OS X that can (re)sign apps and bundle them into ipa files that are ready to be installed on an iOS device.

<a name="static-analysis-tools"></a>
### Static Analysis Tools
- [iLEAPP](https://github.com/abrignoni/iLEAPP) - iOS Logs, Events, And Plist Parser.
- [Keychain Dumper](https://github.com/ptoomey3/Keychain-Dumper) - A tool to check which keychain items are available to an attacker once an iOS device has been jailbroken.
- [BinaryCookieReader](https://github.com/as0ler/BinaryCookieReader) - A tool to read the binarycookie format of Cookies on iOS applications.
- [PList Viewer](https://github.com/TingPing/plist-viewer) - Gtk application to view property list files.
- [XMachOViewer](https://github.com/horsicq/XMachOViewer) - A Mach-O viewer for Windows, Linux and MacOS.
- [MachO-Explorer](https://github.com/DeVaukz/MachO-Explorer) - A graphical Mach-O viewer for macOS. Powered by Mach-O Kit.
- [iFunbox](https://www.i-funbox.com/en/index.html) - A general file management software for iPhone and other Apple products.
- [3uTools](http://www.3u.com/) - An All-in-One management software for iOS devices.
- [iTools](https://www.thinkskysoft.com/itools/) - An All-in-One solution for iOS devices management.

<a name="dynamic-analysis-tools"></a>
### Dynamic Analysis Tools
- [Frida](https://github.com/frida/frida) - Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.
- [frida-gum](https://github.com/frida/frida-gum) - Cross-platform instrumentation and introspection library written in C.
- [Fridax](https://github.com/NorthwaveSecurity/fridax) - Fridax enables you to read variables and intercept/hook functions in Xamarin/Mono JIT and AOT compiled iOS/Android applications.
- [r2frida](https://github.com/nowsecure/r2frida) - Radare2 and Frida better together.
- [r2ghidra](https://github.com/radareorg/r2ghidra) - An integration of the Ghidra decompiler for radare2.
- [iproxy](https://github.com/libimobiledevice/libusbmuxd) - A utility allows binding local TCP ports so that a connection to one (or more) of the local ports will be forwarded to the specified port (or ports) on a usbmux device.
- [itunnel](https://code.google.com/archive/p/iphonetunnel-usbmuxconnectbyport/downloads) - Use to forward SSH via USB.
- [objection](https://github.com/sensepost/objection) - A runtime mobile exploration toolkit, powered by Frida, built to help you assess the security posture of your mobile applications, without needing a jailbreak.
- [Grapefruit](https://github.com/ChiChou/grapefruit) - Runtime Application Instruments for iOS.
- [Passionfruit](https://github.com/chaitin/passionfruit) - Simple iOS app blackbox assessment tool, powered by frida 12.x and vuejs.
- [Runtime Mobile Security (RMS)](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security) - Runtime Mobile Security (RMS), powered by FRIDA, is a powerful web interface that helps you to manipulate Android and iOS Apps at Runtime.
- [membuddy](https://zygosec.com/membuddy.html) - Dynamic memory analysis & visualisation tool for security researchers.
- [unidbg](https://github.com/zhkl0228/unidbg) - Allows you to emulate an Android ARM32 and/or ARM64 native library, and an experimental iOS emulation.
- [Qiling](https://github.com/qilingframework/qiling) - An advanced binary emulation framework.
- [fishhook](https://github.com/facebook/fishhook) - A library that enables dynamically rebinding symbols in Mach-O binaries running on iOS.
- [Dwarf](https://github.com/iGio90/Dwarf) - Full featured multi arch/os debugger built on top of PyQt5 and frida.
- [FridaHookSwiftAlamofire](https://github.com/neil-wu/FridaHookSwiftAlamofire) - A frida tool that capture GET/POST HTTP requests of iOS Swift library 'Alamofire' and disable SSL Pinning.
- [ios-deploy](https://github.com/ios-control/ios-deploy) - Install and debug iOS apps from the command line. Designed to work on un-jailbroken devices.
- [aah](https://github.com/zydeco/aah) - Run iOS arm64 binaries on x86_64 macOS, with varying degrees of success.
- [LLDB](https://lldb.llvm.org/) - A next generation, high-performance debugger. 
- [mitmproxy](https://mitmproxy.org/) - A free and open source interactive HTTPS proxy.
- [Burp Suite](https://portswigger.net/burp) - An advanced HTTPS proxy software.

## Frida Scripts
- [FridaSwiftDump](https://github.com/neil-wu/FridaSwiftDump/) - A Frida script for retriving the Swift Object info from an running app.
- [iOS Jailbreak Detection Bypass](https://github.com/neil-wu/FridaSwiftDump/) - A Frida script used for bypass iOS jailbreak detection by hooking some methods and functions.

## Tweaks

<a name="reverse-engineering-tweaks"></a>
### Reverse Engineering Tweaks
- [FoulDecrypt](https://github.com/NyaMisty/fouldecrypt) - A lightweight and simpling iOS binary decryptor, supports iOS 13.5 and later.
- [iGameGod](https://iosgods.com/repo/) - Cheat Engine, Speed Manager, Auto Touch, Device Spoofer & App Decryptor.
- [CrackerXI](http://cydia.iphonecake.com/) - Tool to Decrypt iOS Apps, based on BFInject, Supports Electra as well as Unc0ver Jailbreaks.
- [flexdecrypt](https://repo.packix.com/) - Command line tool for decrypting Mach-O binaries.
- [Flex 3 Beta](https://getdelta.co/) - Flex gives you the power to modify apps and change their behavior, with no coding experience needed.
- [OpenSSH](https://cydia.saurik.com/package/openssh/) - secure remote access between machines.
- [Apple File Conduit "2"](https://cydia.saurik.com/package/com.saurik.afc2d/) - Unlocks filesystem access over USB on Windows or macOS on jailbroken devices.
- [AppSync Unified](https://cydia.akemi.ai/?page/net.angelxwind.appsyncunified) - Enables the ability to install unsigned/fakesigned iOS applications.
- [NewTerm 2](https://chariz.com/) - A powerful terminal app for iOS.

<a name="static-analysis-tweaks"></a>
### Jailbrek Detection Bypass Tweaks
- [Shadow](https://ios.jjolano.me/depiction/web/me.jjolano.shadow.html) - A lightweight general jailbreak detection bypass tweak.
- [A-Bypass](https://repo.co.kr/package/com.rpgfarm.a-bypass) - A tool that helps block some apps from accessing unauthorized space or calling functions not authorized by Apple due to jailbreak.
- [FlyJB X](https://repo.xsf1re.kr/) - A jailbreak bypass that allows you to bypass the in-app jailbreak detection mechanism.
- [Liberty Lite (Beta)](https://ryleyangus.com/repo/) - A general purpose jailbreak detection bypass patch.
- [vnodebypass](https://cydia.ichitaso.com/) - An expermental tool to hide jailbreak files for bypass detection.
- [KernBypass (Unofficial)](https://cydia.ichitaso.com) - A kernel level jailbreak detection bypass tweak.
- [HideJB](http://cydia.saurik.com/package/com.thuthuatjb.hidejb/) - Bybass jailbreak detection in certain apps.
- [Hestia](https://repo.packix.com/) - A global jailbreak detection bypass tweak.
- [Choicy](http://cydia.saurik.com/package/com.opa334.choicy/) - An advanced tweak configurator.

<a name="dynamic-analysis-tweaks"></a>
### SSL Pinning Bypass Tweaks
- [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2) - A blackbox tool to disable SSL/TLS certificate validation - including certificate pinning - within iOS and macOS applications.
- [SSLBypass](https://github.com/evilpenguin/SSLBypass) - iOS SSL Pinning Bypass (iOS 8 - 14).

## Courses

- [Pentesting iOS Applications](https://www.pentesteracademy.com/course?id=2) - by PentesterAcademy.
- [iOS Pentesting](https://www.youtube.com/playlist?list=PL5Fxd3nu70eyqiqrVlD9QMoaOARr082TA) - by Mantis.
- [iOS Application Pentesting Series](https://www.youtube.com/playlist?list=PLm_U3e1sSTMvgj1sbZ2Ng6VbxMWw8Wyk9) - by Sateesh Verma.
- [IOS: Penetration Testing](https://www.youtube.com/playlist?list=PLanZMaPa4zzyGJ7IiW2zQNC40pWf2-7uE) - by Noisy Hacker.

## Books

- [iOS Hacking Guide](https://web.securityinnovation.com/hacking-ios-applications) - by Security Innovation.
- [iOS Application Security: The Definitive Guide for Hackers and Developers](https://nostarch.com/iossecurity) - by David Thiel.
- [iOS Penetration Testing: A Definitive Guide to iOS Security](https://link.springer.com/book/10.1007/978-1-4842-2355-0) - by Kunal Relan.
- [Learning iOS Penetration Testing](https://www.packtpub.com/product/learning-ios-penetration-testing/9781785883255) - by Swaroop Yermalkar.
- [Hacking and Securing iOS Applications](https://www.oreilly.com/library/view/hacking-and-securing/9781449325213/) - by Jonathan Zdziarski.
- [iOS Hacker's Handbook](https://www.amazon.com/iOS-Hackers-Handbook-Charlie-Miller/dp/1118204123) - by Charlie Miller.

## Tutorials

- [iOS + Frida Tutorial](https://youtu.be/h070-YZKOKE) - A 3-parts tutorial contains an introduction to Frida and iOS, low-level iOS interfaces (GCD, XPC, IOKit, Mach), and Objective-C instrumentation by @naehrdine.
- [Exploiting Common iOS Apps’ Vulnerabilities](https://www.youtube.com/watch?v=RLzbHHoEKo8&t=19s) - @ivRodriguezCA walks through some of the most common vulnerabilities on iOS apps and shows how to exploit them.

## Articles

<a name="penetration-testing-articles"></a>
### Penetration Testing Articles

<a name="reverse-engineering-articles"></a>
### Reverse Engineering Articles

<a name="jailbrek-detection-bypass-articles"></a>
### Jailbrek Detection Bypass Articles

- [Bypass Jailbreak Detection with Frida in iOS applications](https://blog.attify.com/bypass-jailbreak-detection-frida-ios-applications/)
- [iOS Swift Anti-Jailbreak Bypass with Frida](https://syrion.me/blog/ios-swift-antijailbreak-bypass-frida/)
- [Bypassing JailBreak Detection - DVIAv2 Part 2](https://philkeeble.com/ios/reverse-engineering/iOS-Bypass-Jailbreak/)
- [Gotta Catch 'Em All: Frida & jailbreak detection](https://www.romainthomas.fr/post/21-07-pokemongo-anti-frida-jailbreak-bypass/) - Bypass Jailbreak Detection in PokemonGO.

<a name="ssl-pinning-bypass-articles"></a>
### SSL Pinning Bypass Articles

- [SSL Pinning bypass in iOS application](https://sudonull.com/post/10665-SSL-Pinning-bypass-in-iOS-application)
- [Bypass Facebook SSL Certificate Pinning for iOS](https://www.cyclon3.com/bypass-facebook-ssl-certificate-pinning-for-ios)
- [Bypass SSL Pinning with LLDB on AppStore iOS apps](https://itnext.io/bypass-ssl-pinning-with-lldb-in-ios-app-b78f9e7cc9cd)

<a name="checklists-&-CheatSheets"></a>
## Checklists & CheatSheets

- [HackTricks iOS Pentesting Checklist](https://book.hacktricks.xyz/mobile-apps-pentesting/ios-pentesting-checklist)
- [OWASP Mobile Application Security Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs)
- [iOS CheatSheet](https://github.com/randorisec/MobileHackingCheatSheet/blob/master/LEGACY.md#ios-cheatsheet)

## Labs

- [Damn Vulnerable iOS Application (DVIA)](https://damnvulnerableiosapp.com/)
- [OWASP iGoat](https://igoatapp.com/)
- [WaTF Bank](https://github.com/WaTF-Team/WaTF-Bank)
- [Myriam](https://github.com/GeoSn0w/Myriam)


<a name="ctf"></a>
### CTF
- [OWASP UnCrackable Mobile Apps](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes)
- [r2con Crackmes](https://github.com/hexploitable/r2con2020_r2frida)
- [Headbook-CTF](https://github.com/ivRodriguezCA/Headbook-ctf)
- [iOS CTF](https://www.optiv.com/insights/source-zero/blog/walkthrough-ios-ctf)
- [DFA/CCSC Spring 2020 CTF – Apple iOS Forensics with iLEAPP](https://www.petermstewart.net/dfa-ccsc-spring-2020-ctf-apple-ios-forensics-with-ileapp/)
- [NCC Con 2018 iOS CTF](https://ch1kpee.com/2018/01/08/ncc-con-2018-ios-ctf-solutions/)
- [Cellebrite CTF 2021 - Beth's iPhone](https://www.stark4n6.com/2021/10/cellebrite-ctf-2021-beths-iphone.html)

## Writeups

- [Airdrop: Symbolic Link Following](https://breakpoint.sh/posts/airdrop-symbolic-link-following)
- [XSS STORED IN FILES.SLACK.COM VIA XML/SVG FILE (IOS)](https://omespino.com/write-up-xss-stored-in-files-slack-com-via-xml-svg-file-ios-1000-usd/)
- [Facebook iOS address bar spoofing](https://servicenger.com/mobile/facebook-ios-address-bar-spoofing/)


## Misc

- [MOBEXLER](https://mobexler.com/) - A customised virtual machine, designed to help in penetration testing of Android & iOS applications.
- [frida Workbench](https://marketplace.visualstudio.com/items?itemName=CodeColorist.vscode-frida) - Unofficial frida workbench for VSCode.
- [Apple Configurator](https://apps.apple.com/app/apple-configurator-2/id1037126344) - Apple Configurator features a flexible, device-centric design that enables you to configure one or dozens of devices quickly and easily.
- [Corellium](https://www.corellium.com/) - Corellium is the only platform offering ARM-based mobile device virtualization using a custom-built hypervisor for real-world accuracy and high performance.
- [Apple Platform Security](https://support.apple.com/en-gb/guide/security/welcome/web) - Explore Apple Platform Security.
- [IPSW Downloads](https://ipsw.me/) - Download current and previous versions of Apple's iOS, iPadOS, macOS, watchOS, tvOS and audioOS firmware and receive notifications when new firmwares are released.
- [theos](https://github.com/theos/theos) - A cross-platform suite of tools for building and deploying software for iOS and other platforms.
