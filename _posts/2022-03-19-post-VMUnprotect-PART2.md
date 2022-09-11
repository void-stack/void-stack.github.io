---
title: "VMUnprotect Call Hijacker for VMP: Part 2"
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
  - part 2
---

## Now what if... we make an program that does everything for us!
At first I made my approach that tries to search for function `0x06000153` in this sample. Which appears to be invoking functions called in virtualized methods.

![genious](/assets/images/genious.jpg)

![dnspy4](/assets/images/dnspy5.png)

And replace this call with my own middle man invoke. This can be achieved by transpiler from Harmony. Which was my older method.

## My old approach [VmProtectDumperTranspiler.cs](https://github.com/void-stack/VMUnprotect/blob/main/VMUP/VMUnprotect.Runtime/Hooks/Methods/VmProtectDumperTranspiler.cs)

```csharp
/// <summary>A transpiler that replaces all occurrences of a given method with another with additional Ldarg_1 instruction</summary>
/// <param name="instructions">The enumeration of <see cref="T:HarmonyLib.CodeInstruction" /> to act on</param>
/// <param name="from">Method to search for</param>
/// <param name="to">Method to replace with</param>
/// <returns>Modified enumeration of <see cref="T:HarmonyLib.CodeInstruction" /></returns>
private static void ReplaceVmpInvoke(ref IEnumerable < CodeInstruction > instructions, MethodBase @from, MethodBase to) {
    if ((object) from == null) throw new ArgumentException("Unexpected null argument", nameof(from));
    if ((object) to == null) throw new ArgumentException("Unexpected null argument", nameof(to));
    var code = new List < CodeInstruction > (instructions);
    for (var x = 0; x < code.Count; x++) {
        var ins = code[x];
        if (ins.operand as MethodBase != from) continue;
        // replace callvirt Invoke with our debug invoke.
        ins.opcode = OpCodes.Callvirt;
        ins.operand = to;
        // insert additional Ldarg_1 which corresponds to MethodBase of invoked function.
        // TODO: Improve this, can be easily broken by obfuscation or future VMP updates
        code.Insert(x, new CodeInstruction(OpCodes.Ldarg_1));
        Logger.Info("Replaced with custom Invoke and injected MethodBase argument at {0}.", x);
    }
}

/// <summary>A transpiler that alters instructions that calls specific method</summary>
/// <param name="instructions">The enumeration of <see cref="T:HarmonyLib.CodeInstruction" /> to act on</param>
/// <returns>Modified enumeration of <see cref="T:HarmonyLib.CodeInstruction" /></returns>
public static IEnumerable < CodeInstruction > Transpiler(IEnumerable < CodeInstruction > instructions) {
    Logger.Debug("VMP Function Handler Transpiler");
    // Newer version
    ReplaceVmpInvoke(ref instructions, AccessTools.Method(typeof (MethodBase), "Invoke", new [] {
        typeof (object), typeof (BindingFlags), typeof (Binder), typeof (object[]),
        typeof (CultureInfo)
    }), AccessTools.Method(typeof (VmProtectDumperTranspiler), nameof(HookedInvoke)));
    // Older version
    ReplaceVmpInvoke(ref instructions,
        AccessTools.Method(typeof (MethodBase), "Invoke", new [] {
            typeof (object), typeof (object[])
        }),
        AccessTools.Method(typeof (VmProtectDumperTranspiler), nameof(HookedInvokeOld)));
    return instructions;
}
```

And this worked just fine, but it wasn't stable so I didn't bother with it and just did same as Washi.

---

How Harmony works

Where other patch libraries simply allow you to replace the original method, `Harmony` goes one step further and gives you:
- A way to keep the original method intact
- Execute your code before and/or after the original method
- Modify the original with IL code processors
- Multiple Harmony patches co-exist and don't conflict with each other
  
`Prefix` - is a method that is executed before the original method. It is commonly used to:
- access and edit the arguments of the original method
- set the result of the original method
- skip the original method and prefixes that alter its input/result
- set custom state that can be recalled in the postfix

`Postfix` is a method that is executed after the original method. It is commonly used to:
- read or change the result of the original method
- access the arguments of the original method
- make sure your code is always executed
- read custom state from the prefix

`Transpiler` is not a patch method that is executed at runtime when the Original method is called. Instead, you can see it more as a post-compiler stage that can alter the source code of the original method. Except that at runtime, it's not C# but IL code that you change.

[Resources](https://harmony.pardeike.net/articles/intro.html)

```csharp
var invokeMethod = typeof (object).Assembly
    .GetType("System.Reflection.RuntimeMethodInfo")
    .GetMethod("UnsafeInvokeInternal", BindingFlags.NonPublic | BindingFlags.Instance);

prefixMethod = typeof (Program).GetMethod(nameof(InvokePrefix), BindingFlags.Static | BindingFlags.Public);
postfixMethod = typeof (Program).GetMethod(nameof(InvokePostfix), BindingFlags.Static | BindingFlags.Public);
harmony.Patch(invokeMethod, new HarmonyMethod(prefixMethod), new HarmonyMethod(postfixMethod));

public static void InvokePrefix(object __instance, object obj, object[] parameters, object[] arguments) {
    var method = (MethodBase) __instance;
    string returnType = method is MethodInfo info ? info.ReturnType.FullName : "System.Object";
    Console.WriteLine($"--- call to {returnType} {method.DeclaringType}::{method.Name}({string.Join(", ", method.GetParameters().Cast<object>())})");
    if (arguments != null) {
        for (int i = 0; i < arguments.Length; i++)
            Console.WriteLine($"--- {i}: {FormatObject(arguments[i])}");
    }
}

public static void InvokePostfix(object __instance, ref object __result, object obj, object[] parameters, object[] arguments) {
    Console.WriteLine("--- Resulted in " + FormatObject(__result));
}
```

## Current approach [VmProtectDumperUnsafeInvoke](https://github.com/void-stack/VMUnprotect/blob/main/VMUP/VMUnprotect.Runtime/Hooks/Methods/VmProtectDumperUnsafeInvoke.cs)

Since we would be logging all functions called by the assembly, I've added an additional check to make sure the call is coming from VMProtect Call Handler.

```csharp
// Check if this invoke is coming from VMP Handler
var isVmpFunction = structure is {} && new StackTrace().GetFrame(3).GetMethod().MetadataToken ==
  structure.FunctionHandler.MDToken.ToInt32();

if (!isVmpFunction)
  return true;
```

This works same besides that we have additional features like:
- [DebugIsAttachedPatch](https://github.com/void-stack/VMUnprotect/blob/main/VMUP/VMUnprotect.Runtime/Hooks/Methods/AntiDebug/DebugIsAttachedPatch.cs)
- [DebugIsLoggingPatch](https://github.com/void-stack/VMUnprotect/blob/main/VMUP/VMUnprotect.Runtime/Hooks/Methods/AntiDebug/DebugIsLoggingPatch.cs)
- [NtQueryInformationProcessPatch](https://github.com/void-stack/VMUnprotect/blob/main/VMUP/VMUnprotect.Runtime/Hooks/Methods/AntiDebug/NtQueryInformationProcessPatch.cs)


Whole source code on Github: [VMUnprotect][vmup-website]

[vmup-website]: https://github.com/void-stack/VMUnprotect/
[vmp-website]: https://vmpsoft.com
[harmony]: https://github.com/pardeike/Harmony