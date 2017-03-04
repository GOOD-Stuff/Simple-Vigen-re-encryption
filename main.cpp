/**
  @author - Vladimir Gustov
  @mail   - gutstuf@gmail.com
  @note   - This application encrypts the plaintext with the key
                and the alphabet on the encryption method Vigenère
*/
#include <QCoreApplication>
#include <QString>
#include <QByteArray>
#include <iostream>
#include <fstream>
#include <QDebug>
#include <unistd.h>
#include <algorithm>
#include <qalgorithms.h>
#include <string>
#include <sys/stat.h>

#define SUCCESS 0
#define FAILURE 1

using namespace std;
static char *path_key;
static char *path_alph;
static char *path_text;
static int  alph_length = 33;   // default length of alphabet (for cyrillic)
static bool isSpace = false;

static const QString get_keys(ifstream &file);
static const QString get_alph(ifstream &file);
static const QString get_encr_text(const QString colm_alph, const QString key,
                                   const QString clear_text);
static int menu(int argc, char **argv);
static void clear_space(QString &text);
static void clear_enters(QString &text);
static const QString get_text(ifstream &file);

int main(int argc, char **argv) {

    path_key = (char*)calloc(MAX_INPUT, sizeof(char*));
    path_alph = (char*)calloc(MAX_INPUT, sizeof(char*));
    path_text = (char*)calloc(MAX_INPUT, sizeof(char*));    

    if( menu(argc, argv) != 0 )
        return -FAILURE;

    ifstream opt_file(path_key);
    if( !opt_file.is_open()){
        fprintf(stderr, "Can't open file with"
                        " options: %s\r\n", strerror(errno));
        return -FAILURE;
    }

    ifstream alph_file(path_alph);
    if( !alph_file.is_open()){
        fprintf(stderr, "Can't open file with"
                        " alphabets: %s\r\n", strerror(errno));
        opt_file.close();
        return -FAILURE;
    }

    ifstream clear_file(path_text);
    if( !clear_file.is_open()){
        fprintf(stderr, "Can't open file with"
                        " open text: %s\r\n", strerror(errno));
        opt_file.close();
        alph_file.close();
        return -FAILURE;
    }


    const QString colm_alph = get_alph(alph_file);
    if( colm_alph == NULL ){
        opt_file.close();
        alph_file.close();
        clear_file.close();
        return -FAILURE;
    }

    const QString keys = get_keys(opt_file);
    if( keys == NULL ){
        opt_file.close();
        alph_file.close();
        clear_file.close();
        return -FAILURE;
    }


    const QString buff = get_text(clear_file);
    if( buff == NULL ){
        opt_file.close();
        alph_file.close();
        clear_file.close();
        return -FAILURE;
    }

    cout << "\tAll displayed text without whitespace\n";
    cout << "Key phrase: " << keys.toStdString() << endl;
    cout << "Clear text: " << buff.toStdString() << endl;
    cout << "Using alph: " << colm_alph.toStdString() << endl;

    QString shfr_buff = get_encr_text(colm_alph, keys, buff);

    cout << "Encrt text: ";
    cout << shfr_buff.toStdString() << endl;

    ofstream encrt_text("encryption.txt", ios_base::out | ios_base::trunc);
    if( !encrt_text.is_open()){
        fprintf(stderr, "Can't open/create file with"
                        " options: %s\r\n", strerror(errno));
        return -FAILURE;
    }

    encrt_text.write(shfr_buff.toUtf8(), shfr_buff.toUtf8().length());

    opt_file.close();
    alph_file.close();
    clear_file.close();
    encrt_text.close();

    free(path_alph);
    free(path_key);
    free(path_text);

    return SUCCESS;
}

/**
 * @brief menu - Parse input arguments on keys and path to file;
 * @param argc - Count of input arguments;
 * @param argv - Input arguments;
 * @return SUCCESS - If all arguments is normal;
 *         FAILURE - If was error;
 */
static int menu(int argc, char **argv){
    string help = "\tYou must to use:\n"
                  "-k\t- file which contains key phrase;\n"
                  "-a\t- file which contains alphabet for encryption;\n"
                  "-t\t- file which contains plaintext (not encrypted);\n"                  
                  "-h\t- this help view;\n";
    if( ( argc != 7 ) ){
        if( !strcmp(argv[1], "-h") ){
            cout << help << endl;
            return -FAILURE;
        }
        cout << "\tYou doing something wrong!" << endl;
        cout << help << endl;
        return -FAILURE;
    }

    int opt;
    while( (opt = getopt(argc, argv, "k:a:t:h:")) != -1 ){
        switch(opt){
        case 'k':
            cout << "\tYour key file will be: ";
            strcpy(path_key, optarg);
            cout << path_key << endl;
            break;
        case 'a':
            cout << "\tYour alphabet file will be: ";
            strcpy(path_alph, optarg);
            cout << path_alph << endl;
            break;
        case 't':
            cout << "\tYour plaintext file will be: ";
            strcpy(path_text, optarg);
            cout << path_text << endl;            
            break;
        case 'h':
            cout << help << endl;
            return -FAILURE;
        default:
            cout << "\tYou wroooong! Why?" << endl;
            cout << help << endl;
            return -FAILURE;
        }
    }

    return SUCCESS;
}

/**
 * @brief get_key - return key words or phrase for encryption, length of alphabet
 * @param file    - file which contains key words
 * @return s_key_words - if all was successfully, string of key phrase;
 *         NULL        - if was error;
 */
static const QString get_keys(ifstream &file){
    struct stat info_file;
    stat(path_key, &info_file);  // get size of file

    if( info_file.st_size <= 0 ){
        printf("Why your %s is empty? (^o^)\r\n", path_key);
        return NULL;
    }

    char *key_words = (char*)calloc(info_file.st_size, sizeof(char*));
    if( key_words == NULL ){
        printf("Couldn't allocate memory for key words. Sorry (X_X)\r\n");
        return NULL;
    }

    file.read(key_words, info_file.st_size);
    if( !file ) {
        printf("Couldn't read file with keys. Sorry (*-*)\r\n");
        return NULL;
    }

    QString s_key_words(key_words);
    clear_enters(s_key_words);      // Remove only '\n'

    free(key_words);

    return s_key_words;
}

/**
 * @brief get_alph     - return the string of alphabet for encryption;
 * @param file         - file which contains alphabet;
 * @return s_alph_line - if all was successfully, string of alphabet;
 *         NULL        - if was error;
 */
static const QString get_alph(ifstream &file){
    struct stat info_file;
    stat(path_alph, &info_file);

    if( info_file.st_size <= 0 ){   // Check the size of file
        printf("Why your %s is empty? (^o^)\r\n", path_alph);
        return NULL;
    }

    file.seekg(0, ios_base::beg); // Set position into start of file
    alph_length = info_file.st_size;

    char *alph_line = (char*) calloc(alph_length, sizeof(char*));
    if( alph_line == NULL ){
        printf("Couldn't allocate memory for alphabet. Sorry (X_X)\r\n");
        return NULL;
    }

    file.read(alph_line, alph_length);
    if( !file ){
        printf("Couldn't read file with alphabet. Sorry (*-*)\r\n");
        return NULL;
    }

    QString s_alph_line(alph_line);    
    clear_enters(s_alph_line);
    alph_length = s_alph_line.size();

    // Check, if we have space in alphabet,
    // then other must contains it too
    if( s_alph_line.indexOf(' ') != -1 )
        isSpace = true;

    free(alph_line);
    return s_alph_line;
}

/**
 * @brief get_text - return string of text for encryption
 * @param file     - file which contains not encrypted text
 * @return s_text - if all was successfully, string of not encrypted text for encryption;
 *         NULL        - if was error;
 */
static const QString get_text(ifstream &file){
    struct stat info_file;
    stat(path_text, &info_file);

    if( info_file.st_size <= 0 ){   // Check size of file
        printf("Why your %s is empty? (^o^)\r\n", path_text);
        return NULL;
    }

    char *text = (char*) calloc(info_file.st_size, sizeof(char*));
    if( text == NULL ){     // If we can't allocate memory
        printf("Couldn't allocate memory for plaintext. Sorry (X_X)\r\n");
        return NULL;
    }

    file.seekg(0, ios_base::beg);           // Set cursor to start of file
    file.read(text, info_file.st_size);
    if( !file ){
        printf("Couldn't read file with plaintext. Sorry (*-*)\r\n");
        return NULL;
    }

    QString s_text(text);
    clear_enters(s_text);

    free(text);
    return s_text;
}

/**
 * @brief clear_enters - Clear string only from \n symbols;
 * @param text         - String of text (key, alphabet, plain text);
 */
static void clear_enters(QString &text){
    text = text.toLower();
    int pos = 0;
    while( text.contains('\n') ) {
        pos = text.indexOf('\n');
        if( pos != -1 )
            text.remove(pos, 1);
    }
}

/**
 * @brief get_encr_text - Encrypts the plaintext;
 * @param colm_alph     - column of alphabet (actually, it is just row of alphabet);
 * @param key           - Key for encryption;
 * @param clear_text    -
 * @return encr_text    - if all was successfully, string of encrypted text;
 *         NULL         - if was error;
 */
static const QString get_encr_text(const QString colm_alph,
                                      const QString key, const QString clear_text){
    QString encr_text;

    int incr_alph, incr_key, incr_text;
    int pos = 0;
    QString::const_iterator iter_key = key.begin();
    for( QString::const_iterator iter_txt = clear_text.begin(); iter_txt != clear_text.end();
                                       iter_txt++, iter_key++, pos++ ) {
        if( iter_key == key.end() )
            iter_key = key.begin();

        incr_alph = colm_alph.indexOf(*iter_txt);
        if( incr_alph < 0 ){
            encr_text.append(*iter_txt);
            iter_key--;
            continue;
        }

        incr_key = colm_alph.indexOf(*iter_key);
        if( incr_key < 0 ){          
            continue;
        }

        incr_text = incr_alph + incr_key;

        if( incr_text >= alph_length )
            incr_text = abs(incr_text - alph_length);

        encr_text.append(colm_alph.at(incr_text));
    }

    return encr_text;
}

