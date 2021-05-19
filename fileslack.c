/**   INFO8012: Digital Forensics
 *    Lab 4 - File System Analysis
 *
 * By:
 *      BOONEN Antoine
 *      MATAIGNE Florian
 *
 * Date:
 *      14/05/2021
 *
 *  Evidence in evidence.img found and saved as "evidence.pdf"
 *  Also, diagram of the functioning present in tar.gz
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define PARTITION_START 0x01AE
#define SECTOR_SIZE 512

static unsigned long fat_crawling(FILE *fp, unsigned long FAT_address, unsigned long FILE_cluster, unsigned long FAT_size);
static unsigned long name_check(FILE *fp, unsigned long address, char *name, char *type_name, unsigned long max_size);
static int hidden_data_crawl(FILE *fp, unsigned long address, unsigned long file_size, unsigned long full_size);
static unsigned long endian_swap (unsigned long x, int len);
static unsigned long read_bytes(FILE *fp, int number);

int main( int argc, char *argv[] ) {

    char name[16] = "";
    char *disk_name;
    char *full_path_name;

    unsigned long tmp;
    unsigned long partition;

    unsigned long address;
    unsigned long temp_address;

    unsigned long sector;
    unsigned long nbr_of_reserved;

    unsigned long FAT;
    unsigned long FAT_nbr;
    unsigned long FAT_size;
    unsigned long FAT_offset;
    unsigned long FAT_address;

    unsigned long ROOT_offset;
    unsigned long ROOT_cluster;

    unsigned long DIR_cluster;
    unsigned long DIR_offset;

    unsigned long FILE_cluster;
    unsigned long FILE_size;

// ----------------- INITIATING THE PARAMETERS -----------------//
    if(argc != 4) {
        printf("Wrong number of arguments.\n");
        return 2;
    }

    if(!strncmp(argv[2], "part=",5)){
        partition = strtol(argv[2]+5, NULL, 10);
    }else{
        printf("Bad primarypart argument, should be part=number.\n");
        return 2;
    }
    partition = PARTITION_START + (16 * partition);

    if(!strncmp(argv[1], "if=",3)){
        disk_name = argv[1]+3;
    }else{
        printf("Bad disk image name argument, should be if=name.\n");
        return 2;
    }

    FILE *fp;
    fp = fopen(disk_name, "rb");
    if (!fp){
        fprintf(stderr, "Unable to open file: %s", argv[1]);
        return 2;
    }


// ----------------- START OF THE PROGRAM -----------------//

    // we check that we are in FAT32 partition
    fseek( fp, (long)(partition + 4), SEEK_SET );
    if ((tmp = fgetc(fp)) != 0x0c){
        printf("Unsupported file system type: : 0X%02lx\n",tmp);
        return 2;
    }

    // we get the number of sectors btw MBR and partition ( +3, not 4 of current bcs we just read one)
    fseek(fp, 3, SEEK_CUR);
    tmp = read_bytes(fp, 2);
    tmp = endian_swap(tmp, 2);

    // we get the offset = nbr of sectors * sectors size (512)
    address = tmp * SECTOR_SIZE;
    fseek( fp,(long)(address+0x00d), SEEK_SET);
    sector = fgetc(fp);

    // gets the number of reserved sectors
    nbr_of_reserved = read_bytes(fp, 2);
    nbr_of_reserved = endian_swap(nbr_of_reserved, 2);

    // gets the number of FAT
    FAT_nbr = fgetc(fp);

    // gets the of FAT
    fseek( fp,(long)(address+0x024), SEEK_SET);
    FAT = read_bytes(fp, 2);
    FAT = endian_swap(FAT, 2);

    // gets the root cluster
    fseek( fp,(long)(address+0x02c), SEEK_SET);
    ROOT_cluster = read_bytes(fp, 4);
    ROOT_cluster = endian_swap(ROOT_cluster, 4);


    FAT_offset = nbr_of_reserved * SECTOR_SIZE;
    FAT_address = address + FAT_offset;
    FAT_size = FAT * FAT_nbr * SECTOR_SIZE;

    ROOT_offset = (ROOT_cluster - 2) * sector;

    // add all to get to root directory address
    address += FAT_offset +  FAT_size + ROOT_offset;

    // store address in tmp var to manipulate through dir and file walking
    temp_address = address;
    full_path_name = argv[3];

    // 1 because we skip the first "/"
    int cpt = 1;

    //big loop that crawls the whole dir/file name
    while(1){
        // if "/" means end of a dir name
        if(full_path_name[cpt] == '/'){
            // check the dir name is alright
            DIR_cluster = name_check(fp, temp_address, name, "dir", (SECTOR_SIZE*sector));
            if (DIR_cluster == 0){
                printf("Error: wrong dir name: %s\n", name);
                exit(EXIT_FAILURE);
            }
            DIR_offset = (DIR_cluster - 2) * sector * SECTOR_SIZE;
            temp_address += DIR_offset;

            // IMPORTANT, reset name for next dir or file
            strcpy(name, "");

        }else{
            // no separation, we continue concatenating
            char d = (char)toupper(full_path_name[cpt]);
            strncat(name,&d, 1);

            // if end, means that the rest is the name of the actual file we are looking for
            if (cpt == strlen(full_path_name)){

                FILE_cluster = name_check(fp,temp_address,name,"file",(SECTOR_SIZE*sector));
                if (FILE_cluster == 0){
                    printf("Error: wrong file name: %s\n", name);
                    exit(EXIT_FAILURE);
                }
                // after testing file name is correct, we get the file size (place right after the name)
                FILE_size = read_bytes(fp, 4);
                FILE_size = endian_swap(FILE_size, 4);

                break;
            }
        }
        cpt++;
    }

    // first, we check the file size, if greater than sector size, go to fat table to go to last
    if (FILE_size > (sector * SECTOR_SIZE)){
        // change file cluster nbr until last one
        FILE_cluster = fat_crawling(fp, FAT_address, FILE_cluster, FAT_size);
        if (FILE_cluster < 0){
            printf("Error: Something went wrong while FAT crawling.\n");
            exit(EXIT_FAILURE);
        }
        // gets the size of the part of the file in the last sector
        FILE_size = FILE_size % (sector * SECTOR_SIZE);
    }

    // Gets the address of the last sector of a file
    unsigned long FILE_offset;

    FILE_offset = (FILE_cluster - 2) * sector * SECTOR_SIZE;
    address += FILE_offset;

    // LAST: Print the hidden data
    if(!(hidden_data_crawl(fp,(long)(address), FILE_size, sector * SECTOR_SIZE))){
        printf("Error: Something went wrong while hidden data crawling.\n");
        exit(EXIT_FAILURE);
    }

    fclose(fp);
    return(0);
}


/** Once end of file reached, get
 *
 * @param fp: pointer of position in the file
 * @param address: starting address of the last sector of a file
 * @param file_size: size of the file from which find the hidden data
 * @param full_size: full size of the whole sector (end point)
 * @return 1 if data crawling went right, else otherwise
 */
static int hidden_data_crawl(FILE *fp, unsigned long address, unsigned long file_size, unsigned long full_size){

    // starts at end of "true" (not hidden) data
    unsigned long read;
    unsigned long cpt = file_size;
    fseek(fp,(long)(address+file_size), SEEK_SET);

    // Uncomment to directly save the file
    // FILE* f2;
    // f2 = fopen("evidence.pdf", "a");

    // will stop end of sector
    while(cpt < full_size){
        read = fgetc(fp);
        cpt++;
        printf("%c", (char)read);
        // fputc((int)read, f2);
    }
    // fclose(f2);
    return 1;
}


/** Function to crawl the FAT table until finding last cluster number of a file
 *  Only called when size of a file is greater that its initial sectors size
 *
 * @param fp: pointer of position in the file
 * @param FAT_address: address of the FAT table
 * @param FILE_cluster: actual (and starting) cluster number of the file
 * @param FAT_size: size of the FAT table, to avoid exploring further and maybe go in infinite loop if error
 * @return the number of the last cluster of this file
 */
static unsigned long fat_crawling(FILE *fp, unsigned long FAT_address, unsigned long FILE_cluster, unsigned long FAT_size){

    int cpt = 0;
    unsigned long tmp;

    while (FILE_cluster < 0x0ffffff8){
        tmp = FILE_cluster;
        fseek( fp,(long)(FAT_address+ (FILE_cluster*4)), SEEK_SET);
        FILE_cluster = read_bytes(fp, 4);
        FILE_cluster = endian_swap(FILE_cluster, 4);

        // to avoid infinite loop
        cpt += 4;
        if (cpt > FAT_size){
            printf("Error: No file or directory found.\n");
            return 0;
        }
    }
    return tmp;
}


/** Function with actually multiple tasks:
 *      - Goes to the section with the right code, dir or file type
 *      - Checks if the name is the same as the one we are looking for
 *      - if so, get the next bytes to find the cluster number
 *
 * @param fp: pointer of position in the file
 * @param address: starting address in this directory/file
 * @param name: name we want to compare to
 * @param type_name: file or dir to know what we are looking for
 * @param max_size: max size of the root directory to crawl (to avoid infinite loop exploring the whole file and more)
 * @return cluster number if name is good, 0 if not
 */
static unsigned long name_check(FILE *fp, unsigned long address, char *name, char *type_name, unsigned long max_size){

    unsigned long type;
    unsigned long cluster;
    unsigned long tmp;
    int cpt= 0;

    if (!strcmp(type_name, "dir")){
        type = 0x10;
    }else if (!strcmp(type_name, "file")){
        type = 0x20;
    }
    else{
        printf("Error: wrong type of file selected.\n");
        return 0;
    }

    // test if file name attribute
    fseek( fp,(long)(address+0x0b), SEEK_SET);
    tmp = fgetc(fp);

    again:
    // will stop when attribute found
    while(tmp != type){
        fseek(fp, 31, SEEK_CUR);
        tmp = fgetc(fp);

        // to avoid infinite loop
        cpt += 32;
        if (cpt > max_size){
            printf("Error: No file or directory found.\n");
            return 0;
        }
    }

    cpt = 0;
    // we are at the start of filename, go back few bytes
    fseek(fp, -0x00c, SEEK_CUR);
    for (int i=0;i<8;i++){
        // ignores the spaces
        if((tmp = fgetc(fp))!= 0x20){
            if( tmp != ((unsigned long)name[cpt])){
                fseek(fp, 11, SEEK_CUR);
                goto again;
            }
            cpt++;
        }
    }

    // if we end up with right length of name too (ex: if not that, 'filer' would be ok for real 'file')
    if(cpt != strlen(name)){
        return 0;
    }

    // now we are sure name is good
    // thus we get the bytes from HIGH & LOW cluster number
    fseek(fp, 12, SEEK_CUR);
    tmp = read_bytes(fp, 2);
    tmp = endian_swap(tmp, 2);
    cluster = tmp * 0x10000;
    fseek(fp, 4, SEEK_CUR);
    tmp = read_bytes(fp, 2);
    tmp = endian_swap(tmp, 2);
    cluster += tmp;

    return cluster;
}


/** Store amount of bytes from an address in a long
 *
 * @param fp: pointer of position in the file
 * @param number: number of bytes to read (and actually store)
 * @return: the long containing all the bytes read
 */
static unsigned long read_bytes(FILE *fp, int number){
    unsigned long tmp;
    tmp = fgetc(fp);
    for (int i = 1; i<number; i++){
        tmp = tmp * 0x100;
        tmp += fgetc(fp);
    }
    return tmp;
}


/** Function to swap the endianness of the bytes
 *
 * @param x: serie of bytes in a specific endianness
 * @param len: the number of bytes we want to swap endianness
 * @return the same array of bytes in the order endianness order
 */
static unsigned long endian_swap (unsigned long x, int len){

    if (len == 4){
        x = ((x>>24)&0xff) | // move byte 3 to byte 0
            ((x<<8)&0xff0000) | // move byte 1 to byte 2
            ((x>>8)&0xff00) | // move byte 2 to byte 1
            ((x<<24)&0xff000000); // byte 0 to byte 3
    }

    else if (len == 2)
        x = ((x & 0x00FF) << 8) | ((x & 0xFF00) >> 8);
    else{
        printf("Error: Undefined byte length.\n");
        exit(EXIT_FAILURE);
    }
    return x;
}