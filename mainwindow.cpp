#include "mainwindow.h"
#include "ui_mainwindow.h"

string inputFile, outputFile, keyFile;
QString infile, outfile, kfile;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_encrypt_clicked()
{
    int index = 1;
    main_crypt(index);
}

void MainWindow::on_decrypt_clicked()
{
    int index = 2;
    main_crypt(index);
}

void MainWindow::main_crypt(int index)
{

    ifstream inputf;
    inputf.open(inputFile.c_str());
    ofstream outputf;
    outputf.open(outputFile.c_str());
    ifstream keyputf;
    keyputf.open(keyFile.c_str());
    if(!inputf.is_open())
    {
        QMessageBox::information(this,"Error!","Can't open input file!");
        return;
    }
    if(!outputf.is_open())
    {
        QMessageBox::information(this,"Error!","Can't open output file!");
        return;
    }
    if(!keyputf.is_open())
    {
        QMessageBox::information(this,"Error!","Can't open key file!");
        return;
    }

    vector<unsigned char> input = readFile((char*)inputFile.c_str());
    if (input.empty())
    {
        QMessageBox::information(this,"Error!","Can't read input file");
        return;
    }

    vector<unsigned char> key = readFile((char*)keyFile.c_str());
    if (key.size() != 8)
    {
        QMessageBox::information(this,"Error!","Key must be 8 byte!");
        return;
    }

    vector<unsigned char> output;
    if (index == 1)
    {
       output.push_back(8 - input.size() % 8);
       input.insert(input.end(), 8 - input.size() % 8, 0);

       for (int i = 0; i < input.size() / 8; i++)
       {
            vector<unsigned char> input8;
            input8.insert(input8.end(), input.begin() + i * 8, input.begin() + (i + 1) * 8);
            vector<unsigned char> crypted = crypt(input8, key, index);
            output.insert(output.end(), crypted.begin(), crypted.end());
       }
    }
    else
    {
       int num0 = input[0];
       vector<unsigned char> temp;
       temp.insert(temp.begin(), input.begin() + 1, input.end());
       input = temp;

       for (int i = 0; i < input.size() / 8; i++)
       {
            vector<unsigned char> input8;
            input8.insert(input8.end(), input.begin() + i * 8, input.begin() + (i + 1) * 8);

            vector<unsigned char> decrypted = crypt(input8, key, index);
            output.insert(output.end(), decrypted.begin(), decrypted.end());
        }

        for (int i = 0; i < num0; i++)
            output.pop_back();
    }

    ofstream outStream(outputFile.c_str());
    outStream.write((char*)&output.front(), output.size());
    outStream.close();
    QMessageBox::information(this,"Succes!","File is crypted!");
}

vector<unsigned char> MainWindow::readFile(char* fileName)
{
    vector<unsigned char> input;
    ifstream ifst(fileName, ios::binary);
    if (ifst.fail())
        return input;

    ifst.seekg(0, ios::end);
    int size = ifst.tellg();
    ifst.seekg(0, ios::beg);

    input.resize(size);
    ifst.read((char*)&input.front(), size);
    ifst.close();
    return input;
}

vector<unsigned char> MainWindow::crypt(vector<unsigned char> data, vector<unsigned char> key8, int index)
{

    vector<unsigned char> bits;
    vector<unsigned char> key64;
    for (int i = 0; i < 8; i++) //разбиваем байтовые блоки данных на биты
    {
        unsigned char b = data[i];
        unsigned char k = key8[i];
        for (int j = 0; j < 8; j++)
        {
            bits.push_back(b % 2);
            b = b / 2;

            key64.push_back(k % 2);
            k = k / 2;
        }
    }

    if (index == 1) // начальная или обратная перестановка в зависимости от шифровки
        first(bits);
    else
        last(bits);

    vector<unsigned char> left, right; //делим блок данных на 2 половины
    left.insert(left.end(), bits.begin(), bits.begin() + 32);
    right.insert(right.end(), bits.begin() + 32, bits.end());

    vector<vector<unsigned char> > keys = makeKeys(key64); //генерируем ключи

    for (int i = 0; i < 16; i++) //цикл шагов
    {
        if (index == 1)
            step(right, left, keys[i]);
        else
            step(right, left, keys[15 - i]);
    }

    bits.clear();
    bits.insert(bits.end(), right.begin(), right.end());
    bits.insert(bits.end(), left.begin(), left.end());

    if (index == 1) // начальная или обратная перестановка в зависимости от шифровки
        last(bits);
    else
        first(bits);

    vector<unsigned char> result;
    for (int i = 0; i < 8; i++) //складываем биты назад в байт
    {
        unsigned char b = 0;
        unsigned char pow2 = 1;
        for (int j = 0; j < 8; j++)
        {
            b += bits[i * 8 + j] * pow2;
            pow2 *= 2;
        }
        result.push_back(b);
    }

    return result;
}

vector<vector<unsigned char> > MainWindow::makeKeys(vector<unsigned char> key64)
{
    //Матрица G первоначальной подготовки ключа
    int r1[] = {
        57, 49, 41, 33, 25, 17, 9, 1,
        58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3,
        60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15, 7, 62, 54, 46, 38,
        30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 28, 20, 12, 4
    };

    vector<unsigned char> key56(56);
    for (int i = 0; i < 56; i++) //перестановка битов в соответствии с матрицей первоначальной подготовки
    {
        key56[i] = key64[r1[i] - 1];
    }

    //Таблица сдвигов для вычисления ключа
    int shs[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

    //Матрица H завершающей обработки ключа
    unsigned char r2[] = {
        14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32
    };

    vector<vector<unsigned char> > keys;
    for (int j = 0; j < 16; j++) //цикл вычисления ключей для каждого из 16 шагов
    {
        while (shs[j] > 0) //цикл циклического сдвига 28 битовых блоков ключа в соответствии с таблицей
        {
            unsigned char temp1 = key56[0];
            unsigned char temp2 = key56[28];


            for (int i = 0; i < 55; i++) //циклический сдвиг
            {
                if (i == 27)
                    continue;
                else
                    key56[i] = key56[i + 1];
            }
            key56[27] = temp1;
            key56[55] = temp2;
            shs[j] -= 1;
        }

        vector<unsigned char> key48(48);
        for (int i = 0; i < 48; i++) //перестановка битов в соответствии с матрицей завершающей обработки
        {
            key48[i] = key56[r2[i] - 1];
        }
        keys.push_back(key48);
    }
    return keys;
}

void MainWindow::step(vector<unsigned char>& right, vector<unsigned char>& left, vector<unsigned char> key48)
{

    vector<unsigned char> right48(48); //таблица для расширения блока данных
    int E[] = {
        32, 1, 2, 3, 4, 5, 4, 5,
        6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27,
        28, 29, 28, 29, 30, 31, 32, 1
    };

    for (int i = 0; i < 48; i++)//расширение блока данных
    {
        right48[i] = right[E[i] - 1];
    }

    for (int i = 0; i < 48; i++) //сложение XOR с соответствующим ключом
    {
        right48[i] = right48[i] ^ key48[i];
    }

    vector<unsigned char>  newRight32 = convertTo32(right48); //преобразование к 32бит ключу

    unsigned char per[] = { //матрица перестановки P
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    };

    vector<unsigned char>  temp(32); //перестановка в соответствии с матрицей
    for (int i = 0; i < 32; i++)
        temp[i] = newRight32[per[i] - 1];
    newRight32 = temp;

    for (int i = 0; i < 32; i++) //L(i-1) xor f(R(i-1), K(i))
        newRight32[i] = newRight32[i] ^ left[i];

    left = right; // L(i) = R(i - 1)
    right = newRight32; //R(i) = L(i-1) xor f(R(i-1), K(i))
}

vector<unsigned char> MainWindow::convertTo32(vector<unsigned char> right48)
{
    int  sbloki[8][4][16] = { //матрицы преобразования
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,

        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,

        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,

        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,

        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,

        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 12, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,

        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,

        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    };

    unsigned char right8x6[8][6];
    for (int i = 0; i < 8; i++) //48-битовая последовательность разбивается на восемь 6-битовых блоков
    {
        for (int j = 0; j < 6; j++)
        {
            right8x6[i][j] = right48[i * 6 + j];
        }
    }

    vector<unsigned char> newRight32; //формирование в соотв с таблицей
    for (int i = 0; i < 8; i++)
    {

        int row = right8x6[i][0] * 2 + right8x6[i][5];//b1b6 указывает номер строки матрицы

        int column = //b2b3b4b5 - номер столбца
            right8x6[i][1] * 8
            + right8x6[i][2] * 4
            + right8x6[i][3] * 2
            + right8x6[i][4] * 1;

        int sValue = sbloki[i][row][column]; //значение на пересечении нужного столбца и строки

        int sBits[4];
        for (int j = 4; j; j--) //преобразование в 4 битовую последовательность
        {
            sBits[j - 1] = sValue % 2;
            sValue /= 2;
        }

        for (int j = 0; j < 4; j++) //записываем полученные 4 бита
        {
            newRight32.push_back(sBits[j]);
        }
    }
    return newRight32;
}

vector<unsigned char> MainWindow::first(vector<unsigned char> bits)
{
    unsigned char IP[] = { //Матрица начальной перестановки IP
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    vector<unsigned char>  temp(64); //перестановка в соответствии с матрицей
    for (int i = 0; i < 64; i++)
        temp[i] = bits[IP[i] - 1];
    bits = temp;
    return bits;
}

vector<unsigned char> MainWindow::last(vector<unsigned char> bits)
{
    unsigned char IP1[] = { //Матрица обратной перестановки IP-1
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25
    };

    vector<unsigned char>  temp(64); //перестановка в соответствии с матрицей
    for (int i = 0; i < 64; i++)
        temp[i] = bits[IP1[i] - 1];
    bits = temp;
    return bits;
}



void MainWindow::on_Open1_clicked()
{
    infile = QFileDialog::getOpenFileName(this,tr("Открыть файл"),"/Users/","Allfiles(*)");
    inputFile = infile.toStdString();
    ui->label_4->setText(infile);
}

void MainWindow::on_Save_clicked()
{
    outfile = QFileDialog::getSaveFileName(this,tr("Открыть файл"),"/Users/","Allfiles(*)");
    outputFile = outfile.toStdString();
    ui->label_5->setText(outfile);
}

void MainWindow::on_Open2_clicked()
{
    kfile = QFileDialog::getOpenFileName(this,tr("Открыть файл"),"/Users/","Allfiles(*)");
    keyFile = kfile.toStdString();
    ui->label_6->setText(kfile);
}
