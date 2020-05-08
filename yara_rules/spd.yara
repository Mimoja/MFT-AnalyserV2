rule SPD_FILE
{
      meta:
        author="mimoja <coreboot@mimoja.de>"
      strings:
        $SPD4 = {
            (21 | 22 | 23 | 24 )
            (10 | 11)
            (0B | 0C | 0D | 0E | 0F | 10 | 11)
            (00 | 01 | 02 | 03 | 04| 05 | 06 | 08 | 09 | 0D | 0E | 0F)
            (0? | 1? | 3? | 4? | 5?)
            (??)
            (??)
            (0? | 1? | 2?)
            (00)
            (?0)
            (??)
            (00 | 01 | 02 | 03)
            [6]
            (0A | 09 | 08 | 07 | 06 | 05 | 04 | 03)
            /*
            [495]
            ??
            */
        }

     condition:
        $SPD4

}