#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QFileDialog>
#include <QtGui>
#include <QTextStream>
#include <vector>
#include <QDir>
#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>


using namespace std;
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_encrypt_clicked();

    void on_decrypt_clicked();

    void main_crypt(int index);
    //функция шифрования

    vector<unsigned char> crypt(vector<unsigned char> data, vector<unsigned char> key8, int index);

    //функция генерации ключей для каждого из 16 шагов
    vector<vector<unsigned char> > makeKeys(vector<unsigned char> key64);

    //шаг операции
    void step(vector<unsigned char>& right, vector<unsigned char>& left, vector<unsigned char> key48);

    //Функция преобразования 48бит данных к 32
    vector<unsigned char> convertTo32(vector<unsigned char> right48);

    vector<unsigned char> first(vector<unsigned char> bits); //начальная перестановка
    vector<unsigned char> last(vector<unsigned char> bits); //обратная перестановка
    vector<unsigned char> readFile(char* fileName);

    void on_Open1_clicked();

    void on_Save_clicked();

    void on_Open2_clicked();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
