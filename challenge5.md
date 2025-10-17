# TISC CSIT Challenge 5 — SYNTRA

**Category:** RE,Misc
**Challenge:** Reverse engineer an old radio and get the flag.

---

## Summary

We are given a corrupted binary file syntra-server and an endpoint running the same program.
Interacting with the endpoint shows that it behaves like an old radio where we can tune, skip, and play songs.
This suggests that we probably need to make it play a special track to reveal the flag.

Running command ```file syntra-server ``` tells us that the meta data of the file claims that it is in big endian but the file is LSB. With the help of chatgpt, we edit the metadata of the file and we can now run the programme locally. 

Running ```strings syntra-server | grep flag```, we see a suspicious output somewhere in the binary: asset/flag.mp3. I decided to use ghidra to analyse the binary. 

The binary is in go and I installed the go plugin for ghidra:
https://github.com/felberj/gotools.

Examining the decompiled binary, I observed the following function call chain:
main.main.func2() → parseMetrics() → main.determineAudioResource() → main.evaluateMetricsQuality() → main.computeMetricsBaseline().
Inside main.determineAudioResource(), I found:
```C
if (main.evaluateMetricsQuality() != 0) {
    return "assets";  
}
```
This means main.evaluateMetricsQuality() and main.computeMetricsBaseline() has the main logic for us to get the flag. 

In computeMetricsBaseline(), the program parses a constant calibrationData into a slice of 32-bit values, applies another constant correctionFactors using XOR, and then converts each 32-bit value into a 3-word triplet [upper16, lower16, 0].
evaluateMetricsQuality() uses this baseline, collects non-4 triplets from the input, and checks if they match exactly.
The checking logic includes some conditional handling — for instance, if the first value in a triplet is 5 or 6, it compares the second value differently — but overall, as long as all triplets match, the check passes.

Using GDB I ran the programme and set a breakpoint just before computeMetricsBaseline() returns and got the final list of 3-word triplets:

```scss
(1,0,0)
(5,3,0)
(6,7,0)
(2,0,0)
(5,1,0)
(6,2,0)
(1,0,0)
(5,6,0)
(6,5,0)
(3,0,0)
(5,4,0)
(6,0,0)
```

Now this brings me to the next question: How should our input be formatted to be processed correctly? 
I realised the input is being processed by parseMetrics(). From reversing and stepping through in GDB, we can tell that this function constructs a new internal object and copies several key fields from the provided input slice:
1. the data pointer,
2. the number of triples (length), and
3. a checksum field.
   
Next, the function loops through the input slice, processing triples (each triple = 3 × 4-byte words). For each iteration, it copies the triple into an internal buffer and updates a running counter stored at puVar13[3].
Once all triples are processed, the function XORs all the 4-byte words from the parsed data to generate a checksum. This computed checksum is then compared against the original checksum field from the input.

### Solution
I constructed my input based on this, did a lot more debugging locally, sent the post request and we got the flag!


**Flag:** 
TISC{PR3551NG_BUTT0N5_4ND_TURN1NG_KN0B5_4_S3CR3T_S0NG_FL4G}
