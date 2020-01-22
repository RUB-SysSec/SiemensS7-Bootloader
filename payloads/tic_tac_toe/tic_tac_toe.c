#include <stdbool.h>
#include <stdint.h>

#include "../lib/print.h"
#include "../lib/read.h"
#include "../lib/stdlib.h"
//#include "../lib/string.h"
#include "memory.h"

char greeting[] = "Welcome to tic-tac-toe\n";

int doit(unsigned char *, unsigned char *) __attribute__((noinline));
int checkwin();
void board();
int main();

int _start(unsigned char *read_buf, unsigned char *write_buf) {
    __asm__("stmfd sp!, {r2-r12, lr}");
    __asm__("adr r9, _start");
    
    int res = doit(read_buf, write_buf);

    __asm("ldmfd sp!, {r2-r12, lr}");
    return res;
}

int doit(unsigned char *read_buf, unsigned char *write_buf) {
    char buf[0x20];

    memset(buf, 0, 0x20);

    memcpy(buf, greeting, sizeof(greeting)-1);

    UART_protocol_send_single(buf, sizeof(greeting)-1);

    main();

    write_buf[0] = 0;
    return 0;
}

char square[10] = { 'o', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
char msg_enter_num[] = "Player X, enter a number\n";
char msg_game_win[] = " ==> Player X wins";
char msg_game_draw[] = "==> Game draw";
char msg_invalid_move[] = "Invalid move ";

char board_buf[] = "\n\n\tTic Tac Toe\n\n" \
    "Player 1 (X)  -  Player 2 (O)\n\n\n" \
    "     |     |     \n" \
    "  X  |  X  |  X \n" \
    "_____|_____|_____\n" \
    "     |     |     \n" \
    "  X  |  X  |  X \n" \
    "_____|_____|_____\n" \
    "     |     |     \n" \
    "  X  |  X  |  X \n" \
    "     |     |     \n\n";

int main()
{
    int player = 1, i;
    char choice;
    // char *board_buffer = RW_BUF;
    char mark;
    do
    {
        board();
        player = (player % 2) ? 1 : 2;

        msg_enter_num[7] = '0' + player;
        UART_protocol_send_single(msg_enter_num, sizeof(msg_enter_num)-1);
        UART_protocol_recv_chunk(&choice, 1);
        choice -= 0x30;

        mark = (player == 1) ? 'X' : 'O';

        if (choice == 1 && square[1] == '1')
            square[1] = mark;
            
        else if (choice == 2 && square[2] == '2')
            square[2] = mark;
            
        else if (choice == 3 && square[3] == '3')
            square[3] = mark;
            
        else if (choice == 4 && square[4] == '4')
            square[4] = mark;
            
        else if (choice == 5 && square[5] == '5')
            square[5] = mark;
            
        else if (choice == 6 && square[6] == '6')
            square[6] = mark;
            
        else if (choice == 7 && square[7] == '7')
            square[7] = mark;
            
        else if (choice == 8 && square[8] == '8')
            square[8] = mark;
            
        else if (choice == 9 && square[9] == '9')
            square[9] = mark;
            
        else
        {
            UART_protocol_send_single(msg_invalid_move, sizeof(msg_invalid_move)-1);
            player--;
        }
        i = checkwin();
        player++;
    } while (i ==  - 1);
    
    board();
    
    if (i == 1) {
        msg_game_win[12] = '0' + (--player);
        UART_protocol_send_single(msg_game_win, sizeof(msg_game_win) - 1);
    }
    else
        UART_protocol_send_single(msg_game_draw, sizeof(msg_game_draw) - 1);

    return 0;
}

/*********************************************

FUNCTION TO RETURN GAME STATUS
1 FOR GAME IS OVER WITH RESULT
-1 FOR GAME IS IN PROGRESS
O GAME IS OVER AND NO RESULT
 **********************************************/

int checkwin()
{
    if (square[1] == square[2] && square[2] == square[3])
        return 1;
        
    else if (square[4] == square[5] && square[5] == square[6])
        return 1;
        
    else if (square[7] == square[8] && square[8] == square[9])
        return 1;
        
    else if (square[1] == square[4] && square[4] == square[7])
        return 1;
        
    else if (square[2] == square[5] && square[5] == square[8])
        return 1;
        
    else if (square[3] == square[6] && square[6] == square[9])
        return 1;
        
    else if (square[1] == square[5] && square[5] == square[9])
        return 1;
        
    else if (square[3] == square[5] && square[5] == square[7])
        return 1;
        
    else if (square[1] != '1' && square[2] != '2' && square[3] != '3' &&
        square[4] != '4' && square[5] != '5' && square[6] != '6' && square[7] 
        != '7' && square[8] != '8' && square[9] != '9')

        return 0;
    else
        return  - 1;
}


/*******************************************************************
FUNCTION TO DRAW BOARD OF TIC TAC TOE WITH PLAYERS MARK
 ********************************************************************/

char indices[] = {68,
        74,
        80,
        121,
        127,
        133,
        174,
        180,
        186};

void board()
{
    /* 
    68
    74
    80
    121
    127
    133
    174
    180
    186
    */
    
    for (int i = 0; i <= sizeof(indices); ++i) {
        board_buf[(int)indices[i]] = square[i + 1];
    }

    UART_protocol_send_single(board_buf, sizeof(board_buf) - 1);
}

/*******************************************************************
END OF PROJECT
 ********************************************************************/