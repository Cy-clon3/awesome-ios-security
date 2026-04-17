<!--lint ignore double-link-->

<!--lint disable awesome-heading-->
# Awesome iOS Security <a href="https://github.com/Cy-clon3/awesome-ios-security/"><img src="https://awesome.re/badge.svg" alt="Awesome"></a>

<a href="https://github.com/Cy-clon3/awesome-ios-security/"><img src="https://upload.wikimedia.org/wikipedia/commons/5/56/IOS_15_logo.png" align="right" width="70" alt="iOS 15"></a>

> [<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/1/1b/Apple_logo_grey.svg/30px-Apple_logo_grey.svg.png" width="16">]() A curated list of awesome iOS application security resources.

<!--lint enable double-link-->

A collection of awesome tools, books, courses, blog posts, and cool stuff about iOS Application Security and Penetration Testing.

---

## Contents

- [Tools](#tools)
  - [Reverse Engineering Tools](#reverse-engineering-tools)
  - [Static Analysis Tools](#static-analysis-tools)
  - [Dynamic Analysis Tools](#dynamic-analysis-tools)
- [Tweaks](#tweaks)
  - [Reverse Engineering Tweaks](#reverse-engineering-tweaks)
  - [Jailbrek Detection Bypass Tweaks](#jailbrek-detection-bypass-tweaks)
  - [SSL Pinning Bypass Tweaks](#ssl-pinning-bypass-tweaks)
- [Frida Scripts](#frida-scripts)
- [Courses](#courses)
- [Books](#books)
- [Sessions & Workshops](#sessions--workshops)
- [Articles & Tutorials](#articles--tutorials)
  - [Penetration Testing Articles](#penetration-testing-articles)
  - [Reverse Engineering Articles](#reverse-engineering-articles)
  - [Jailbrek Detection Bypass Articles](#jailbrek-detection-bypass-articles)
  - [SSL Pinning Bypass Articles](#ssl-pinning-bypass-articles)
- [Checklists & Cheatsheets](#checklists--cheatsheets)
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
- [flexdecrypt](https://github.com/JohnCoates/flexdecrypt) - An iOS App & Mach-O binary decryptor.
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
- [AltStore](https://altstore.io/) - Allows to sideload other apps (.ipa files) onto iOS device.
- [iOS App Signer](https://github.com/DanTheMan827/ios-app-signer) - An app for macOS that can (re)sign apps and bundle them into ipa files that are ready to be installed on an iOS device.

<a name="static-analysis-tools"></a>
### Static Analysis Tools
- [iLEAPP](https://github.com/abrignoni/iLEAPP) - An iOS Logs, Events, And Plist Parser.
- [Keychain Dumper](https://github.com/ptoomey3/Keychain-Dumper) - A tool to check which keychain items are available to an attacker once an iOS device has been jailbroken.
- [BinaryCookieReader](https://github.com/as0ler/BinaryCookieReader) - A tool to read the binarycookie format of Cookies on iOS applications.
- [PList Viewer](https://github.com/TingPing/plist-viewer) - Gtk application to view property list files.
- [XMachOViewer](https://github.com/horsicq/XMachOViewer) - A Mach-O viewer for Windows, Linux and macOS.
- [MachO-Explorer](https://github.com/DeVaukz/MachO-Explorer) - A graphical Mach-O viewer for macOS. Powered by Mach-O Kit.
- [iFunbox](https://www.i-funbox.com/en/index.html) - A general file management software for iPhone and other Apple products.
- [3uTools](http://www.3u.com/) - An All-in-One management software for iOS devices.
- [iTools](https://www.thinkskysoft.com/itools/) - An All-in-One solution for iOS devices management.

<a name="dynamic-analysis-tools"></a>
### Dynamic Analysis Tools
- [Corellium](https://www.corellium.com/) - The only platform offering ARM-based mobile device virtualization using a custom-built hypervisor for real-world accuracy and high performance.
- [Frida](https://github.com/frida/frida) - Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.
- [frida-gum](https://github.com/frida/frida-gum) - Cross-platform instrumentation and introspection library written in C.
- [Fridax](https://github.com/NorthwaveSecurity/fridax) - Fridax enables you to read variables and intercept/hook functions in Xamarin/Mono JIT and AOT compiled iOS/Android applications.
- [r2frida](https://github.com/nowsecure/r2frida) - Radare2 and Frida better together.
- [r2ghidra](https://github.com/radareorg/r2ghidra) - An integration of the Ghidra decompiler for radare2.
- [iproxy](https://github.com/libimobiledevice/libusbmuxd) - A utility allows binding local TCP ports so that a connection to one (or more) of the local ports will be forwarded to the specified port (or ports) on a usbmux device.
- [itunnel](https://code.google.com/archive/p/iphonetunnel-usbmuxconnectbyport/downloads) - Use to forward SSH via USB.
- [objection](https://github.com/sensepost/objection) - A runtime mobile exploration toolkit, powered by Frida, built to help you assess the security posture of your mobile applications, without needing a jailbreak.
- [NullKia](https://github.com/bad-antics/nullkia) - Mobile security framework supporting 18 manufacturers including Apple, with baseband exploitation, TEE research, and eSIM security tools.
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

## Tweaks

<a name="reverse-engineering-tweaks"></a>
### Reverse Engineering Tweaks
- [FoulDecrypt](https://github.com/NyaMisty/fouldecrypt) - A lightweight and simpling iOS binary decryptor, supports iOS 13.5 and later.
- [iGameGod](https://iosgods.com/repo/) - Cheat Engine, Speed Manager, Auto Touch, Device Spoofer & App Decryptor.
- [CrackerXI](http://cydia.iphonecake.com/) - Tool to Decrypt iOS Apps, based on BFInject, Supports Electra as well as Unc0ver Jailbreaks.
- [flexdecrypt](https://repo.packix.com/) - Command line tool for decrypting Mach-O binaries.
- [Flex 3 Beta](https://getdelta.co/) - Flex gives you the power to modify apps and change their behavior, with no coding experience needed.
- [Frida](https://build.frida.re) - Frida server for iOS.
- [OpenSSH](https://cydia.saurik.com/package/openssh/) - Secure remote access between machines.
- [Apple File Conduit "2"](https://cydia.saurik.com/package/com.saurik.afc2d/) - Unlocks filesystem access over USB on Windows or macOS on jailbroken devices.
- [AppSync Unified](https://cydia.akemi.ai/?page/net.angelxwind.appsyncunified) - Enables the ability to install unsigned/fakesigned iOS applications.
- [NewTerm 2](https://chariz.com/) - A powerful terminal app for iOS.
- [Filza File Manager](http://cydia.saurik.com/package/com.tigisoftware.filza/) - A Powerful File Manager for iOS with IPA Installer, DEB Installer, Web viewer, and Terminal.

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
- [SSLBypass](https://github.com/evilpenguin/SSLBypass) - An iOS SSL Pinning Bypass Tweak (iOS 8 - 14).

## Frida Scripts
- [FridaSwiftDump](https://github.com/neil-wu/FridaSwiftDump/) - A Frida script for retriving the Swift Object info from an running app.
- [iOS 13 SSL Bypass](https://codeshare.frida.re/@federicodotta/ios13-pinning-bypass/) - SSL Pinning Bypass for iOS 13.
- [iOS 12 SSL Bypass](https://codeshare.frida.re/@machoreverser/ios12-ssl-bypass/) - SSL Pinning Bypass for iOS 12.
- [iOS Jailbreak Detection Bypass](https://codeshare.frida.re/@liangxiaoyi1024/ios-jailbreak-detection-bypass/) - A Frida script used for bypass iOS jailbreak detection by hooking some methods and functions.
- [iOS App Static Analysis](https://codeshare.frida.re/@interference-security/ios-app-static-analysis/) - Script for iOS app's static analysis.
- [Touch ID Bypass](https://highaltitudehacks.com/2018/07/26/ios-application-security-part-50-touch-id-bypass-with-frida/) - A Frida script for iOS Touch/Face ID Bypass.

## Courses

- [Pentesting iOS Applications](https://www.pentesteracademy.com/course?id=2) - By PentesterAcademy.
- [iOS Pentesting](https://www.youtube.com/playlist?list=PL5Fxd3nu70eyqiqrVlD9QMoaOARr082TA) - By Mantis.
- [iOS Application Pentesting Series](https://www.youtube.com/playlist?list=PLm_U3e1sSTMvgj1sbZ2Ng6VbxMWw8Wyk9) - By Sateesh Verma.
- [IOS: Penetration Testing](https://www.youtube.com/playlist?list=PLanZMaPa4zzyGJ7IiW2zQNC40pWf2-7uE) - By Noisy Hacker.

## Books

- [iOS Hacking Guide](https://web.securityinnovation.com/hacking-ios-applications) - By Security Innovation.
- [iOS Application Security: The Definitive Guide for Hackers and Developers](https://nostarch.com/iossecurity) - By David Thiel.
- [iOS Penetration Testing: A Definitive Guide to iOS Security](https://link.springer.com/book/10.1007/978-1-4842-2355-0) - By Kunal Relan.
- [Learning iOS Penetration Testing](https://www.packtpub.com/product/learning-ios-penetration-testing/9781785883255) - By Swaroop Yermalkar.
- [Hacking and Securing iOS Applications](https://www.oreilly.com/library/view/hacking-and-securing/9781449325213/) - By Jonathan Zdziarski.
- [iOS Hacker's Handbook](https://www.amazon.com/iOS-Hackers-Handbook-Charlie-Miller/dp/1118204123) - By Charlie Miller.

## Sessions & Workshops

- [iOS + Frida Tutorial](https://youtu.be/h070-YZKOKE) - A 3-parts workshop contains an introduction to Frida and iOS, low-level iOS interfaces (GCD, XPC, IOKit, Mach), and Objective-C instrumentation by @naehrdine.
- [Exploiting Common iOS Apps' Vulnerabilities](https://www.youtube.com/watch?v=RLzbHHoEKo8&t=19s) - A session by @ivRodriguezCA that walks through some of the most common vulnerabilities on iOS apps and shows how to exploit them.
- [iOS Reverse Engineering With Frida](https://www.youtube.com/watch?v=miSg0Km2V-w) - How to get started in iOS RE with any PC/Mac, an iPhone, and Frida by @x71n3.
- [iOS Application Vulnerabilities and how to find them](https://www.youtube.com/watch?v=2CKrw7ErzCY) - How to get started with hacking iOS apps, environment requirement, play ground etc. by @0ctac0der.

## Articles & Tutorials

<a name="penetration-testing-articles"></a>
### Penetration Testing Articles

- [A Comprehensive guide to iOS Penetration Testing](https://www.getastra.com/blog/security-audit/ios-penetration-testing/)
- [Getting Started with iOS Penetration Testing](https://blog.yeswehack.com/yeswerhackers/getting-started-ios-penetration-testing-part-1/)
- [iOS Pentesting 101](https://www.cobalt.io/blog/ios-pentesting-101)
- [Insecure iOS Storage - DVIAv2](https://philkeeble.com/ios/Insecure-iOS-Storage/)

<a name="reverse-engineering-articles"></a>
### Reverse Engineering Articles

- [iOS Pentesting Tools Part 1: App Decryption and class-dump](https://www.allysonomalley.com/2018/08/10/ios-pentesting-tools-part-1-app-decryption-and-class-dump/)
- [Anti Anti Hooking/Debugging - DVIAv2](https://philkeeble.com/ios/reverse-engineering/iOS-Anti-Anti-Hooking/)
- [Runtime Manipulation - DVIAv2](https://philkeeble.com/ios/reverse-engineering/iOS-Runtime-Manipulation/)
- [Reverse Engineering iOS Apps - iOS 11 Edition](https://ivrodriguez.com/reverse-engineer-ios-apps-ios-11-edition-part2/)


<a name="jailbrek-detection-bypass-articles"></a>
### Jailbrek Detection Bypass Articles

- [Bypass Jailbreak Detection with Frida in iOS applications](https://blog.attify.com/bypass-jailbreak-detection-frida-ios-applications/)
- [iOS Swift Anti-Jailbreak Bypass with Frida](https://syrion.me/blog/ios-swift-antijailbreak-bypass-frida/)
- [Bypassing JailBreak Detection - DVIAv2](https://philkeeble.com/ios/reverse-engineering/iOS-Bypass-Jailbreak/)
- [Gotta Catch 'Em All: Frida & jailbreak detection](https://www.romainthomas.fr/post/21-07-pokemongo-anti-frida-jailbreak-bypass/)

<a name="ssl-pinning-bypass-articles"></a>
### SSL Pinning Bypass Articles

- [SSL Pinning bypass in iOS application](https://sudonull.com/post/10665-SSL-Pinning-bypass-in-iOS-application)
- [Bypass Facebook SSL Certificate Pinning for iOS](https://www.cyclon3.com/bypass-facebook-ssl-certificate-pinning-for-ios)
- [Bypass SSL Pinning with LLDB on AppStore iOS apps](https://itnext.io/bypass-ssl-pinning-with-lldb-in-ios-app-b78f9e7cc9cd)

<a name="checklists-cheatsheets"></a>
## Checklists & Cheatsheets

- [HackTricks iOS Pentesting Checklist](https://book.hacktricks.xyz/mobile-apps-pentesting/ios-pentesting-checklist)
- [OWASP Mobile Application Security Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs)
- [iOS CheatSheet](https://github.com/randorisec/MobileHackingCheatSheet/blob/master/LEGACY.md#ios-cheatsheet)
- [iOS Client-Side Attacks and Tests](https://appsec-labs.com/ios-attacks-tests/)

## Labs

- [Damn Vulnerable iOS Application (DVIA)](https://damnvulnerableiosapp.com/)
- [OWASP iGoat](https://igoatapp.com/)
- [WaTF Bank](https://github.com/WaTF-Team/WaTF-Bank)
- [Myriam](https://github.com/GeoSn0w/Myriam)

## CTF
- [OWASP UnCrackable Mobile Apps](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes)
- [r2con Crackmes](https://github.com/hexploitable/r2con2020_r2frida)
- [Headbook-CTF](https://github.com/ivRodriguezCA/Headbook-ctf)
- [iOS CTF](https://www.optiv.com/insights/source-zero/blog/walkthrough-ios-ctf)
- [DFA/CCSC Spring 2020 CTF – Apple iOS Forensics with iLEAPP](https://www.petermstewart.net/dfa-ccsc-spring-2020-ctf-apple-ios-forensics-with-ileapp/)
- [NCC Con 2018 iOS CTF](https://ch1kpee.com/2018/01/08/ncc-con-2018-ios-ctf-solutions/)
- [Cellebrite CTF 2021 - Beth's iPhone](https://www.stark4n6.com/2021/10/cellebrite-ctf-2021-beths-iphone.html)

## Writeups

- [A deep dive into an NSO zero-click iMessage exploit: Remote Code Execution](https://googleprojectzero.blogspot.com/2021/12/a-deep-dive-into-nso-zero-click.html)
- [Airdrop: Symbolic Link Following](https://breakpoint.sh/posts/airdrop-symbolic-link-following)
- [XSS STORED IN FILES.SLACK.COM VIA XML/SVG FILE (IOS)](https://omespino.com/write-up-xss-stored-in-files-slack-com-via-xml-svg-file-ios-1000-usd/)
- [Facebook iOS address bar spoofing](https://servicenger.com/mobile/facebook-ios-address-bar-spoofing/)

## Misc

- [iOS Jailbreak Downloads](https://idevicecentral.com/jailbreak-tools/ios-jailbreak-downloads-download-jailbreak-tools-for-all-ios-versions/) - Download Jailbreak Tools for All iOS Versions.
- [MOBEXLER](https://mobexler.com/) - A customised virtual machine, designed to help in penetration testing of Android & iOS applications.
- [frida Workbench](https://marketplace.visualstudio.com/items?itemName=CodeColorist.vscode-frida) - Unofficial frida workbench for VSCode.
- [Apple Configurator](https://apps.apple.com/app/apple-configurator-2/id1037126344) - Apple Configurator features a flexible, device-centric design that enables you to configure one or dozens of devices quickly and easily.
- [Apple Platform Security](https://support.apple.com/en-gb/guide/security/welcome/web) - Explore Apple Platform Security.
- [IPSW Downloads](https://ipsw.me/) - Download current and previous versions of Apple's iOS, iPadOS, macOS, watchOS, tvOS and audioOS firmware and receive notifications when new firmwares are released.
- [theos](https://github.com/theos/theos) - A cross-platform suite of tools for building and deploying software for iOS and other platforms.

## Contributing

Your contributions are always welcome! Please read the [contribution guidelines](contributing.md) first.
