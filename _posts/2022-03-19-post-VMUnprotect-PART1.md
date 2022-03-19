---
title: "VMUnprotect Call Hijacker for VMP: Part 1"
classes: wide
tagline: "Have you ever wanted your dynamic analysis tool to log every call made from virtualized VMProtect methods, while having additional features mixed with it?
Well, me neither, but the technology is here and it’s quite simple! This post will introduce a tool made for virtualized malware with the VMProtect.   "
header:
  overlay_image: /assets/images/.jpg
  caption: "![Meme](/assets/images/meme_vmp.jpg)"
categories:
  - Blog
tags:
  - dotnet
  - vmprotect
  - virtualization
  - harmony
  - vmp
  - callhijacker
  - vmunprotect
  - part 1
---


# Hello fellow readers!
This is my exploration of [VMProtect][vmp-website] security. It's well-known  Software Protection with a lot of features, the main ones are code mutation and virtualization. I will talk about all of those in future posts, but now I will focus on virtualization.

![Showcase](https://raw.githubusercontent.com/void-stack/VMUnprotect/main/docs/show.gif)

## About Virtualization and design approach.
VMUnprotect is a project engaged in hunting virtualized VMProtect methods. It makes use of [Harmony][harmony] to dynamically read **VMP** behavior. Currently only supports method administration. Works on **VMProtect 3.5.1** (Latest) and few versions back.

> As VMProtect describes it on their's website. Code virtualization is the next step in software protection. Most protection systems encrypt the code and then decrypt it at the application’s startup. VMProtect doesn’t decrypt the code at all! Instead, the encrypted code runs on a virtual CPU that is markedly different from generic x86 and x64 CPUs as the command set is different for each protected file.

But we're not devirtualizing code at all. What we are doing is done dynamically!

```csharp
// Author: Washi (https://github.com/Washi1337 - https://rtn-team.cc/)
 
using System;
using System.Collections;
using System.Linq;
using System.Reflection;
using HarmonyLib;
 
namespace ConsoleApplication4
{
    internal class Program
    {
        private static FieldInfo _stackField;
        private static FieldInfo _pcField;
 
        public static void Main(string[] args)
        {
            var assembly = Assembly.LoadFile(@"awesome.vmp_nodbg.exe");
            
            var harmony = new Harmony("com.example.patch");
 
            var vmType = assembly.GetType("4775349C");
            var readMethod = vmType.GetMethod("15154B6D", BindingFlags.Instance | BindingFlags.NonPublic);
            _stackField = vmType.GetField("6BAE5C1B", BindingFlags.Instance | BindingFlags.NonPublic);
            _pcField = vmType.GetField("58392466", BindingFlags.Instance | BindingFlags.NonPublic);
            
            var prefixMethod = typeof(Program).GetMethod(nameof(ReadBytePrefix), BindingFlags.Static | BindingFlags.Public);
            var postfixMethod = typeof(Program).GetMethod(nameof(ReadBytePostfix), BindingFlags.Static | BindingFlags.Public);
            
            harmony.Patch(readMethod, new HarmonyMethod(prefixMethod), new HarmonyMethod(postfixMethod));
 
            var invokeMethod = typeof(object).Assembly
                .GetType("System.Reflection.RuntimeMethodInfo")
                .GetMethod("UnsafeInvokeInternal", BindingFlags.NonPublic | BindingFlags.Instance);
            
            prefixMethod = typeof(Program).GetMethod(nameof(InvokePrefix), BindingFlags.Static | BindingFlags.Public);
            postfixMethod = typeof(Program).GetMethod(nameof(InvokePostfix), BindingFlags.Static | BindingFlags.Public);
            harmony.Patch(invokeMethod, new HarmonyMethod(prefixMethod), new HarmonyMethod(postfixMethod));
            
            assembly.EntryPoint.Invoke(null, null);
        }
 
        private static string FormatObject(object obj)
        {
            try
            {
                switch (obj)
                {
                    case null:
                        return "null";
 
                    case string x:
                        return $"\"{x}\"";
 
                    case IEnumerable enumerable:
                        return
                            $"{obj.GetType().Name} {string.Join(", ", enumerable.Cast<object>().Select(FormatObject))}";
 
                    case { } o when o.GetType().Name == "0FE23521":
                    {
                        var field = o.GetType().GetField("5BE47E90", BindingFlags.Instance | BindingFlags.NonPublic);
                        return FormatObject(field.GetValue(o));
                    }
                    case { } o when o.GetType().Name == "6F9B56A3":
                    {
                        var field = o.GetType().GetField("1B4E1C53", BindingFlags.Instance | BindingFlags.NonPublic);
                        return FormatObject(field.GetValue(o));
                    }
                    default:
                        return obj.ToString();
                }
            }
            catch (Exception ex)
            {
                return "???";
            }
        }
 
        public static void ReadBytePrefix(object __instance)
        {
            Console.Write("{0:X8} ({0}): ", _pcField.GetValue(__instance));
            var stackContents = ((IEnumerable) _stackField.GetValue(__instance))
                .Cast<object>()
                .Reverse()
                .ToArray();
            Console.WriteLine(FormatObject(stackContents));
        }
 
        public static void ReadBytePostfix()
        {
        }
        
        public static void InvokePrefix(object __instance, object obj, object[] parameters, object[] arguments)
        {
            var method = (MethodBase) __instance;
            string returnType = method is MethodInfo info ? info.ReturnType.FullName : "System.Object";
            Console.WriteLine($"--- call to {returnType} {method.DeclaringType}::{method.Name}({string.Join(", ", method.GetParameters().Cast<object>())})");
            if (arguments != null)
            {
                for (int i = 0; i < arguments.Length; i++)
                    Console.WriteLine($"--- {i}: {FormatObject(arguments[i])}");
            }
        }
 
        public static void InvokePostfix(object __instance, ref object __result, object obj, object[] parameters, object[] arguments)
        {
            Console.WriteLine("--- Resulted in " + FormatObject(__result));
        }
    }
}
```

![Washi](/assets/images/washi.png)

This piece of code might look complicated at first, but this is what inspired me to make VMUP.  When we look at **Washi** notes from [Tuts4You](https://forum.tuts4you.com/topic/42437-vmprotect-v3501213/) and we look at sample ourselves in [DnspyEx](https://github.com/dnSpyEx/dnSpy) which is a Revival of the well-known .NET debugger and assembly editor, dnSpy.

![dnspy](/assets/images/dnspy1.png)

We can see that methods are empty. This is part of VMProtect protection which can be defeated by placing a breakpoint in `cctor` (right-click on the module and Go to `<Module>. cctor`) and debugging the application. **I also made a tool that does that for you [VMProtect.Dumper](https://github.com/void-stack/VMUnprotect.Dumper)**.

**(If you can't see Modules)**
![dnspy3](/assets/images/dnspy3.png)

![dnspy1](/assets/images/dnspy2.png)

![dnspy4](/assets/images/dnspy4.png)

Voila! We can see juicy code now and a part that Validates password isn't virtualized LOL! It's 
only protected by delegates and mutation. This isn't the point of this article to clean those but Washi made some notes that we can use to explore VM (VMP always injects their VM because they virtualize most of their features for example Anti Debug that is running before main in `<Module>. cctor`).

If we press `Ctrl + D` and type `0x04000048` we now now this is **virtual program counter**. Same goes for `0x0400004A` - **stack**. Previous harmony script performs a VM trace that dumps the program counter, stack contents, and calls.

## What’s next?
In Part 2 we’ll put the described how my older approach was made and how current works.

[vmup-website]: https://github.com/void-stack/VMUnprotect/
[vmp-website]: https://vmpsoft.com
[harmony]: https://github.com/pardeike/Harmony