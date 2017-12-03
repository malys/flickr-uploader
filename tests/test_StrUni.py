# content of test_StrUni.py

import StrUni

def test_Unicode():
    for i in range(1,127):
        assert StrUni.isThisStringUnicode(chr(i)) == False
        assert StrUni.isThisStringUnicode(unicode(chr(i).decode('utf-8'))) == True
        
def test_RUN():
    for j in range(1,366):
        for h in range(23):
            for m in range(60):
                # print('{}.{:0>2d}.{:0>2d}'.format(j, h, m))
                # xRun = eval(('int("{}")+int("{:0>2d}")*100+int("{:0>2d}")'.format(j, h, m)))
                # Run = eval(time.strftime('int("%j")+int("%H")*100+int("%M")'))
                # print Run, xRun
                assert (1 <= eval(('int("{}")+int("{:0>2d}")*100+int("{:0>2d}")'.format(j, h, m))) <= 2724) == True
                assert (1 <= eval(time.strftime('int("%j")+int("%H")*100+int("%M")')) <= 2724) == True

