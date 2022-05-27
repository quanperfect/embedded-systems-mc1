#include <stdio.h>
#include <Windows.h>

int main()
{
    printf("Program started.\n");

    FILE* exeFileInput;
    fopen_s(&exeFileInput, "PortableExecutable.exe", "rb");
    FILE* txtHeadersOutput;
    fopen_s(&txtHeadersOutput, "HeadersInformation.txt", "w");
    FILE* txtBinaryOutput;
    fopen_s(&txtBinaryOutput, "BinaryCode.txt", "wb");
    

    if (!exeFileInput) {
        printf("Failed to open file.\n");
        fprintf(txtHeadersOutput, "Failed to open file.\n");
        exit(1);
    }

    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS mainPeHeader;
    IMAGE_SECTION_HEADER sectionHeader;
    IMAGE_SECTION_HEADER codeHeader;



    fread(&dosHeader, sizeof(dosHeader), 1, exeFileInput);
       
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("File format is not PE (Portable Executable).\n");
        fprintf(txtHeadersOutput, "File format is not PE (Portable Executable).\n");
        exit(1);
    }

    fseek(exeFileInput, dosHeader.e_lfanew, SEEK_SET);
    fread(&mainPeHeader, sizeof(IMAGE_NT_HEADERS), 1, exeFileInput);

    if (mainPeHeader.Signature != IMAGE_NT_SIGNATURE) {
        printf("File IMAGE_NT_SIGNATURE is wrong.\n");
        fprintf(txtHeadersOutput, "File IMAGE_NT_SIGNATURE is wrong.\n");
        exit(1);
    }

    fprintf(txtHeadersOutput, "Signature: %lx \n", mainPeHeader.Signature);
    fprintf(txtHeadersOutput, "Amount of sections: %d \n", mainPeHeader.FileHeader.NumberOfSections);
    fprintf(txtHeadersOutput, "Entry point address: %08lu \n", mainPeHeader.OptionalHeader.AddressOfEntryPoint);

    fprintf(txtHeadersOutput, "\n");

    for (int i = 0; i < mainPeHeader.FileHeader.NumberOfSections; i++) {
        fread(&sectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, exeFileInput);
        fprintf(txtHeadersOutput, "{\n");

        fprintf(txtHeadersOutput, "\tVirtual size: %lu\n", sectionHeader.Misc.VirtualSize);
        fprintf(txtHeadersOutput, "\tRaw size: %lu\n", sectionHeader.SizeOfRawData);
        fprintf(txtHeadersOutput, "\tVirtual address: %lu\n", sectionHeader.VirtualAddress);
        fprintf(txtHeadersOutput, "\tRaw address: %lu\n", sectionHeader.PointerToRawData);

        fprintf(txtHeadersOutput, "}\n");


        if (strcmp((const char*)sectionHeader.Name, ".text") == 0) {
            codeHeader = sectionHeader;
        }
    }

    fseek(exeFileInput, codeHeader.PointerToRawData, 0);

    char* data = (char*)malloc(codeHeader.SizeOfRawData);

    fread(data, sizeof(char), codeHeader.SizeOfRawData, exeFileInput);
    fwrite(data, sizeof(char), codeHeader.SizeOfRawData, txtBinaryOutput);
    free(data);


    fclose(exeFileInput);
    fclose(txtHeadersOutput);
    fclose(txtBinaryOutput);

    printf("Section Data: HeadersInformation.txt\n");
    printf("Binary Code: BinaryCode.txt\n");
    printf("Program completed successfully.\n\n");

    return 0;
}


/*

MS-DOS
PE File Header (+signature)
PE File Optional Header (reserved?)
Section Table
.text Section header (binary code)
.bss section header (declared but not assigned variables)
.rdata section header (read-only data)
...


characteristics - is it dll or obj or exe


*/