from PyQt5 import QtWidgets, QtGui, QtCore
from main2 import Ui_MainWindow
from proccess import Ui_Form
from first_scene import init_scene
from key_generation import Ui_keygeneration
import des


class MainWindow(QtWidgets.QMainWindow):    #主視窗
    def __init__(self):
        # in python3, super(Class, self).xxx = super().xxx
        super(MainWindow, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle("welcome to encrypt and decrypt system!!!")     #主視窗標題
        self.setup_control()

    def setup_control(self):
        # TODO
        # self.ui.keyinput.setText('Happy World!')
        self.ui.EncryptButton.clicked.connect(self.press_en)    #click encrypt按鍵->執行press_en
        self.ui.DecryptButton.clicked.connect(self.press_de)    #click decrypt按鍵->執行press_de

    def press_en(self):
        error_flag = 0  
        des.KEY = self.ui.keyinput.text()   #get key
        msg = self.ui.textinput.text()      #get plaintext
        if len(des.KEY) != 10:  #防呆
            self.ui.condition_label.setText("KEY input length error")
            error_flag = 1
        else:
            for ch in des.KEY:
                if ch != '1' and ch != '0':     #if key 含非0/1之數字->錯誤
                    self.ui.condition_label.setText("key input must be 1 or 0")
                    error_flag = 1
                    break
        if len(msg) != 8:   #防呆
            self.ui.condition_label.setText("text input length error")
            error_flag = 1
        else:
            for ch in msg:
                if ch != '1' and ch != '0':     #if key 含非0/1之數字->錯誤
                    error_flag = 1
                    self.ui.condition_label.setText(
                        "text input must be 1 or 0")
                    break
        if error_flag == 0:     #key,plaintext皆合法
            first_window.setWindowTitle("encryption")   #進入encrypt畫面
            scene.label.setPixmap(QtGui.QPixmap(
                "figure/encryption_first_sceen.png"))
            scene.textinput.setText(msg)    #print plaintext
            scene.textoutput.setText(des.encrypt(msg))  #print ciphertext
            scene.pushButton.clicked.connect(self.encrypt)  #點按鍵->開啟S-DES加密過程視窗
            first_window.show()

    def press_de(self):
        error_flag = 0
        des.KEY = self.ui.keyinput.text()   #get key
        msg = self.ui.textinput.text()      #get ciphertext
        if len(des.KEY) != 10:
            self.ui.condition_label.setText("KEY input length error")
            error_flag = 1
        else:
            for ch in des.KEY:  #防呆
                if ch != '1' and ch != '0':     #if key 含非0/1之數字->錯誤
                    self.ui.condition_label.setText("key input must be 1 or 0")
                    error_flag = 1
                    break
        if len(msg) != 8:   #防呆
            self.ui.condition_label.setText("text input length error")
            error_flag = 1
        else:
            for ch in msg:
                if ch != '1' and ch != '0':     #if key 含非0/1之數字->錯誤
                    error_flag = 1
                    self.ui.condition_label.setText(
                        "text input must be 1 or 0")
                    break
        if error_flag == 0:     #key,ciphertext皆合法
            first_window.setWindowTitle("decryption")   #進入decrypt畫面
            scene.label.setPixmap(QtGui.QPixmap(
                "figure/decryption_first_sceen.png"))
            scene.textinput.setText(msg)    #print ciphertext
            scene.textoutput.setText(des.decrypt(msg))  #print plaintext
            scene.pushButton.clicked.connect(self.decrypt)  #點按鍵->開啟S-DES解密過程視窗
            first_window.show()

    def encrypt(self):  #S-DES加密過程視窗
        ui.label.setPixmap(QtGui.QPixmap("figure/encryption_structure.png"))
        proccess.setWindowTitle("encryption")
        des.KEY = self.ui.keyinput.text()
        msg = self.ui.textinput.text()
        ui.textinput.setText(msg)
        IP = des.permutate(msg, des.IP) #IP
        ui.IP.setText(IP)

        EP = des.permutate(des.right_half(IP), des.EP)  #EP
        ui.EP_1.setText(EP)
        bits = des.xor(EP, des.key1())  #XOR
        S0_1 = des.lookup_in_sbox(des.left_half(bits), des.S0)  #S0 
        ui.S0_1.setText(S0_1)
        S1_1 = des.lookup_in_sbox(des.right_half(bits), des.S1) #S1
        ui.S1_1.setText(S1_1)
        bits = S0_1 + S1_1
        bits = des.permutate(bits, des.P4)  #P4
        ui.P4_1.setText(bits)        
        
        temp = des.f_k(IP, des.key1()) #fk
        after_swap = des.right_half(IP)+temp    #SW
        
        EP = des.permutate(des.right_half(after_swap), des.EP)  #EP
        ui.EP_2.setText(EP)
        bits = des.xor(EP, des.key2())  #XOR
        S0_2 = des.lookup_in_sbox(des.left_half(bits), des.S0)  #S0
        ui.S0_2.setText(S0_2)
        S1_2 = des.lookup_in_sbox(des.right_half(bits), des.S1) #S1
        ui.S1_2.setText(S1_2)
        bits = S0_2 + S1_2
        bits = des.permutate(bits, des.P4)  #P4
        ui.P4_2.setText(bits)
        bits = des.f_k(after_swap, des.key2())      
        ui.IP_inverse.setText(des.permutate(bits + temp, des.IP_INVERSE))   #IP-1

        ui.textoutput.setText(des.encrypt(msg))
        ui.key_button.clicked.connect(self.key_maker)
        proccess.show()

    def decrypt(self):      ##S-DES解密過程視窗
        ui.label.setPixmap(QtGui.QPixmap("figure/decryption_structure.png"))
        proccess.setWindowTitle("decryption")
        des.KEY = self.ui.keyinput.text()
        msg = self.ui.textinput.text()
        ui.textinput.setText(msg)

        IP = des.permutate(msg, des.IP) #IP
        ui.IP.setText(IP)

        EP = des.permutate(des.right_half(IP), des.EP)  #EP
        ui.EP_1.setText(EP)
        bits = des.xor(EP, des.key2())  #XOR
        S0_1 = des.lookup_in_sbox(des.left_half(bits), des.S0)  #S0
        ui.S0_1.setText(S0_1)
        S1_1 = des.lookup_in_sbox(des.right_half(bits), des.S1) #S1
        ui.S1_1.setText(S1_1)
        bits = S0_1 + S1_1
        bits = des.permutate(bits, des.P4)  #P4
        ui.P4_1.setText(bits)        
        
        temp = des.f_k(IP, des.key2())
        after_swap = des.right_half(IP)+temp    #SW
        
        EP = des.permutate(des.right_half(after_swap), des.EP)  #EP
        ui.EP_2.setText(EP)
        bits = des.xor(EP, des.key1())
        S0_2 = des.lookup_in_sbox(des.left_half(bits), des.S0)  #S0
        ui.S0_2.setText(S0_2)
        S1_2 = des.lookup_in_sbox(des.right_half(bits), des.S1) #S1
        ui.S1_2.setText(S1_2)
        bits = S0_2 + S1_2
        bits = des.permutate(bits, des.P4)  #P4
        ui.P4_2.setText(bits)
        bits = des.f_k(after_swap, des.key1())      
        ui.IP_inverse.setText(des.permutate(bits + temp, des.IP_INVERSE))   #IP-1

        ui.textoutput.setText(des.decrypt(msg))
        ui.key_button.clicked.connect(self.key_maker)
        proccess.show()

    def key_maker(self):    #key generation
        key_ui.keyinput.setText(des.KEY)
        key_ui.P10.setText(des.key_P10())   #P10
        key_ui.shift1.setText(des.left_half(des.key_shift1()))  #左半key shift1
        key_ui.shift1_2.setText(des.right_half(des.key_shift1()))   #右半key shift1
        key_ui.shift2.setText(des.left_half(des.key_shift2()))  #左半key shift2
        key_ui.shift2_2.setText(des.right_half(des.key_shift2()))   #右半key shift2
        key_ui.P8.setText(des.key1())   #P8
        key_ui.P8_2.setText(des.key2())     #P8
        key_window.show()


if __name__ == '__main__':
    import sys
    app = QtWidgets.QApplication(sys.argv)

    first_window = QtWidgets.QWidget()  # press encryption or decryption
    scene = init_scene()
    scene.setupUi(first_window)

    proccess = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(proccess)

    key_window = QtWidgets.QWidget()
    key_ui = Ui_keygeneration()
    key_ui.setupUi(key_window)

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
