#include <stdio.h>
#include <string.h>

#define NUM_FRAMES 3
#define REF_LEN 12


void part_a_raw_buffer_demo(void)
{
    printf("======================================================================\n");
    printf("PART A: 4-Element Raw Memory Buffer Demonstration\n");
    printf("======================================================================\n");

    int buffer[4] = {0};

   printf("Initial buffer: [0, 0, 0, 0]\n");

    printf("Empty buffer: [0, 0, 0, 0]\n");

    int values_to_load[4] = {10, 200, 55, 128};

    for (int address = 0; address < 4; address++)
    {
        buffer[address] = values_to_load[address];
        printf("Store -> Memory Cell[%d] = %d\n", address, values_to_load[address]);
    }

    printf("\nBuffer contents:\n");

    for (int address = 0; address < 4; address++)
        printf("Memory Cell[%d] = %d\n", address, buffer[address]);

    int *ptr = buffer;

    printf("\nReading memory using pointer dereferencing:\n");

    for (int i = 0; i < 4; i++)
    {
        printf("Address: %p -> *(ptr + %d) = %d\n",
               (void *)(ptr + i),
               i,
               *(ptr + i));
    }

    int second_array[3] = {77,240,5};

    printf("\nSecond array: [%d,%d,%d]\n",
           second_array[0],
           second_array[1],
           second_array[2]);
}


void translate_address(int logical_address,
                       int page_size,
                       int *page_number,
                       int *offset)
{
    *page_number = logical_address / page_size;
    *offset = logical_address % page_size;
}

void part_b_address_translation(int page_size)
{
    printf("\n======================================================================\n");
    printf("PART B: Paging - Address Translation (page size = 4 bytes)\n");
    printf("======================================================================\n");

    int logical_addresses[] = {0,3,4,9,15,22};

    int n = sizeof(logical_addresses)/sizeof(logical_addresses[0]);

    for(int i=0;i<n;i++)
    {
        int page,offset;

        translate_address(
            logical_addresses[i],
            page_size,
            &page,
            &offset);

        printf("%d -> Page %d Offset %d\n",
               logical_addresses[i],
               page,
               offset);
    }
}


void print_frames(int frames[], int count)
{
    printf("[");

    for(int i=0;i<count;i++)
    {
        printf("%d",frames[i]);

        if(i<count-1)
            printf(", ");
    }

    printf("]");
}

int fifo_page_replacement(int reference_string[], int ref_len, int num_frames)
{
    int frames[NUM_FRAMES];
    int count = 0;
    int front = 0;
    int page_faults = 0;

    printf("\n--- FIFO trace (frames = %d) ---\n", num_frames);
    printf("%4s | %9s | %7s | Frame contents\n", "Ref", "Hit/Fault", "Evicted");

    for (int i = 0; i < ref_len; i++)
    {
        int page = reference_string[i];
        int hit = 0;

        for (int f = 0; f < count; f++)
        {
            if (frames[f] == page)
            {
                hit = 1;
                break;
            }
        }

        int evicted = -1;

        if (!hit)
        {
            page_faults++;

            if (count >= num_frames)
            {
                evicted = frames[front];
                frames[front] = page;
                front = (front + 1) % num_frames;
            }
            else
            {
                frames[count] = page;
                count++;
            }
        }

        printf("%4d | %9s | ", page, hit ? "HIT" : "FAULT");

        if (evicted == -1)
            printf("%7s | ", "-");
        else
            printf("%7d | ", evicted);

        print_frames(frames, count);
        printf("\n");
    }

    return page_faults;
}


int lru_page_replacement(int reference_string[], int ref_len, int num_frames)
{
    int frames[NUM_FRAMES];
    int last_used[NUM_FRAMES];
    int count = 0;
    int page_faults = 0;
    int clock = 0;

    printf("\n--- LRU trace (frames = %d) ---\n", num_frames);
    printf("%4s | %9s | %7s | Frame contents\n", "Ref", "Hit/Fault", "Evicted");

    for (int i = 0; i < ref_len; i++)
    {
        int page = reference_string[i];
        clock++;

        int hit = 0;
        int hit_slot = -1;

        for (int f = 0; f < count; f++)
        {
            if (frames[f] == page)
            {
                hit = 1;
                hit_slot = f;
                break;
            }
        }

        int evicted = -1;

        if (hit)
        {
            last_used[hit_slot] = clock;
        }
        else
        {
            page_faults++;

            if (count >= num_frames)
            {
                int lru_slot = 0;

                for (int f = 1; f < count; f++)
                {
                    if (last_used[f] < last_used[lru_slot])
                        lru_slot = f;
                }

                evicted = frames[lru_slot];
                frames[lru_slot] = page;
                last_used[lru_slot] = clock;
            }
            else
            {
                frames[count] = page;
                last_used[count] = clock;
                count++;
            }
        }

        printf("%4d | %9s | ", page, hit ? "HIT" : "FAULT");

        if (evicted == -1)
            printf("%7s | ", "-");
        else
            printf("%7d | ", evicted);

        print_frames(frames, count);
        printf("\n");
    }

    return page_faults;
}


void part_c_and_d_replacement_algorithms(int *fifo_out,
                                         int *lru_out,
                                         int *total_out)
{
    printf("======================================================================\n");
    printf("PART C: Page Replacement Algorithms - FIFO vs LRU\n");
    printf("======================================================================\n");

    int reference_string[REF_LEN] =
    {
        1,2,3,4,1,2,5,1,2,3,4,5
    };

    int num_frames = NUM_FRAMES;

    printf("Reference string : [1, 2, 3, 4, 1, 2, 5, 1, 2, 3, 4, 5]\n");
    printf("Number of frames : %d\n", num_frames);

    int fifo_faults =
        fifo_page_replacement(reference_string,
                              REF_LEN,
                              num_frames);

    int lru_faults =
        lru_page_replacement(reference_string,
                             REF_LEN,
                             num_frames);

    printf("\n--- Summary ---\n");

    printf("%-10s%8s%8s%14s%12s\n",
           "Algorithm",
           "Faults",
           "Hits",
           "Fault Ratio",
           "Hit Ratio");

    int total = REF_LEN;

    int hits_fifo = total - fifo_faults;
    int hits_lru = total - lru_faults;

    printf("%-10s%8d%8d%13.2f%%%11.2f%%\n",
           "FIFO",
           fifo_faults,
           hits_fifo,
           (fifo_faults * 100.0) / total,
           (hits_fifo * 100.0) / total);

    printf("%-10s%8d%8d%13.2f%%%11.2f%%\n",
           "LRU",
           lru_faults,
           hits_lru,
           (lru_faults * 100.0) / total,
           (hits_lru * 100.0) / total);

    *fifo_out = fifo_faults;
    *lru_out = lru_faults;
    *total_out = total;
}


int main(void)
{
    printf("Task 2: Memory Management Simulation\n");

    part_a_raw_buffer_demo();

   part_b_address_translation(4);

  int fifo_f, lru_f, total;

    part_c_and_d_replacement_algorithms(
        &fifo_f,
        &lru_f,
        &total);

    printf("\n======================================================================\n");
    printf("PART D: Comparative Analysis\n");
    printf("======================================================================\n");

    if (fifo_f > lru_f)
    {
        printf("LRU outperformed FIFO on this workload (%d vs %d faults out of %d references) because LRU evicts the page least recently accessed, which better matches this reference string's temporal locality than FIFO's pure arrival-order eviction.\n",
               lru_f,
               fifo_f,
               total);
    }
    else if (lru_f > fifo_f)
    {
        printf("FIFO outperformed LRU on this workload (%d vs %d faults out of %d references).\n",
               fifo_f,
               lru_f,
               total);
    }
    else
    {
        printf("Both algorithms produced the same number of faults (%d out of %d) on this particular reference string.\n",
               fifo_f,
               total);
    } 

    return 0;
}
