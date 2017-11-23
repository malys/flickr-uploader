# content of test_StrUni.py

import StrUni

def test_Unicode():
    for i in range(1,127):
        assert StrUni.isThisStringUnicode(chr(i)) == False
        assert StrUni.isThisStringUnicode(unicode(chr(i).decode('utf-8'))) == True
