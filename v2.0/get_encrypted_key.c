#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h>
#include "jansson.h"
#include <b64/cdecode.h>

int main() {


    //Abrindo o arquivo Local State, onde se encontrada a encrypted key.
    json_error_t error;

    json_t *json = json_load_file("Local State.json", 0 , &error);

    if (!json) {

        fprintf(stderr, "Arquivo não encontrado.\n"); //erro
        return 1;
    }

    //procurando chave json os_crypt.
    json_t *os_crypt = json_object_get(json, "os_crypt");

    if (!os_crypt) {

        fprintf(stderr, "Chave não encontrada.\n"); //erro
        return 1;
    }

    else {
    printf("Chave os_crypt encontrada...\n");
 
    }

    //encontrando a chave encrypted_key
    json_t *encrypted_key = json_object_get(os_crypt, "encrypted_key");

    if (!encrypted_key) {
        fprintf(stderr, "Encrypted key não encontrada.\n"); //erro
        json_decref(json);
        return 1;
    }
    else if (!json_is_string(encrypted_key)) //verificando se é uma string
    {
        fprintf(stderr, "Encrypted_Key não é uma String\n");//erro
        json_decref(json);
        return 1;
    }
    

    //exibindo a chave, ainda em Base64
    printf("Encrypted key: %s\n", json_string_value(encrypted_key));

    const char *encrypted_key_str = json_string_value(encrypted_key);

//Decodificação da Encrypted Key em Base64

base64_decodestate state;
base64_init_decodestate(&state);

int input_len = strlen(encrypted_key_str);
int decoded_buffer_size = input_len * 3 / 4 +1;

char *decoded_output = malloc(decoded_buffer_size);
if (!decoded_output) {

    fprintf(stderr, "Erro\n");
    json_decref(json);
    return 1;
}

int decoded_length = base64_decode_block (
encrypted_key_str,
strlen(encrypted_key_str),
decoded_output,
&state

);

printf("Decoded key: %s\n", decoded_output);

char *dpapi_data = 0;
int dpapi_len = 0;

printf("Decodificando DPAPI...\n");
if (decoded_length > 5) { 
    dpapi_data = decoded_output + 5;   
    dpapi_len = decoded_length - 5;
 // Pulando os 5 primeiros bytes, pois são uma string "DPAPI", o resto é o que interessa.
}

printf("len: %i, output: %s", dpapi_len, dpapi_data);


DATA_BLOB entrada;
            entrada.pbData = (BYTE *)dpapi_data; 
            entrada.cbData = dpapi_len;

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

                wprintf(L"Chave descriptografada: %.*s\n", saida.cbData / sizeof(WCHAR), (WCHAR *)saida.pbData);
                LocalFree(saida.pbData);
            }
            else
            {

                printf("Erro ao descriptografar com CryptUnprotectData.\n"); //erro
            }

    
printf("Finalizando...\n");
free(decoded_output);
json_decref(json);
return 0;
}
