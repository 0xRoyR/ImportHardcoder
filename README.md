
# ImportHardcoder
##### Written by [Roy Rahamim](https://twitter.com/RBoomboom12312)
This tool hardcodes in an input executable a dependency of a new dll, and outputs the result to a new file.
It achieves this goal by copying the original ```IMAGE_IMPORT_DESCRIPTOR``` structs to the end of the executable and adding to the end of it another struct that describes our dll.

## Usage
The tool takes 3 arguments:
* ```inFile``` - Path of the executable which we want to add dependency to.
* ```dllName``` - <ins>Name</ins> of the dll to be added.
* ```outFile``` - Path of the file which we want to write the output (the new executable) to.

## Technique
Here I will elaborate about what the tool does in depth.
1. Opens the executable using the function ```CreateFileA```.
2. Gets the size of the executable and reads it to memory using the functions ```GetFileSize```, ```ReadFile```.
3. Parses the PE and copies the ```IMAGE_IMPORT_DESCRIPTOR``` structs to a new array called ```pImportDescriptors```.
4. Gets the RVA of the end of the executable.
5. Creates new ILT (Import Lookup Table) for our dll called ```newImportLookupTable``` (of type ```IMAGE_THUNK_DATA``` array of length of 2).
6. Calculates the size we need to append to the last section (and add it to the last section's current size).
7. Makes sure the last section has ```IMAGE_SCN_MEM_READ```, ```IMAGE_SCN_MEM_WRITE``` permissions.
8. Adds 2 additional entries to ```pImportDescriptors```. The first entry is the ```IMAGE_IMPORT_DESCRIPTOR``` struct that describes our dll, and the second entry is the terminating ```IMAGE_IMPORT_DESCRIPTOR``` struct.
9. Sets the Image Data Directory Pointer (```dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]```) to point to the end of the execuable (hence, point to the location of ```pImportDescriptors```).
10. Copies ```pImportDescriptors``` to after the original executable.
11. Copies ```dllName``` to after ```pImportDescriptors```.
12. Copies ```newImportLookupTable``` to after ```dllName```.
13. Writes the result to ```outFile```. If ```outFile``` already exists, The program exists without saving the output (!).

## Ideas & Recommandations
After using this tool, we can drop our dll in the new executable's directory or in one of the known paths. That will force the new execuable to use our dll in addition to all the other dlls that it loads regularly.
I heavily recommand replacing ```inFile``` with ```outFile``` using tool like SilentReplacer, which will make it harder for defenders to detect any changes to the executable that you have used the tool on.


## Notes
Please note that this tool only applies to x64 executables at the moment.

## Credits
Apart from me ([Roy Rahamim](https://twitter.com/RBoomboom12312)), I would also like to credit [x86matthew](https://twitter.com/x86matthew).
When I was in the middle of the process of writing my tool, I have noticed that he has already written the same tool and I got inspired of some little ideas of his, and added them to my implementation of this tool.
