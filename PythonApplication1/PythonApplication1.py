# coding=utf-8
import Crypto.Hash.SHA256 as SHA256
import Crypto.PublicKey.RSA as RSA
import os
import codecs
import Crypto.Signature.PKCS1_v1_5 as PKCS1_v1_5
import time
import dash
import dash_core_components as dcc
import dash_html_components as html
import sys
import chilkat
 
plaintext = "Kompjuterika"
print ("Beginning of RSA")
class rsa1:
    hash = SHA256.new(plaintext)
    result=[]
    resultt=[]
    for i in range(21):
        key=RSA.generate(1024)
        privateKey = key.exportKey()
        publicKey = key.publickey().exportKey()
        private_key = RSA.importKey(privateKey)
        public_key = RSA.importKey(publicKey)
        #signature
        start_time = time.time()
        signer = PKCS1_v1_5.new(private_key)
        signature = signer.sign(hash)
        hexify = codecs.getencoder('hex')
        s = hexify(signature)[0]
        print("Signature: "+s)
        end_time = time.time() - start_time
        print ("Signature time:")
        print end_time
        #verify
        starttime = time.time()
        verify = signer.verify(hash, signature)
        print verify
        endtime = time.time() - starttime
        print("Verification time:")
        print endtime
        result.append(float(end_time))
        resultt.append(float(endtime))
        print("")
        

p=rsa1()
print ("End of RSA")
print("")
print("Beginning of DSA")
class dsa1:
    dsa = chilkat.CkDsa()
    success = dsa.UnlockComponent("Anything for 30-day trial")
    if (success != True):
        print(dsa.lastErrorText())
        sys.exit()
    result1=[]
    result2=[]
    for j in range(21):
         success = dsa.GenKey(1024)
         #public key
         pemPublic = dsa.toPublicPem()
         success = dsa.SaveText(pemPublic,"dsa_pub.pem")
         #privateKey
         pemPrivate = dsa.toPem()
         success = dsa.SaveText(pemPrivate,"dsa_priv.pem")
         hash1=SHA256.new(plaintext).digest()
         hexify = codecs.getencoder('hex')
         s = hexify(hash1)[0]
         #signature
         start_time1=time.time()
         success = dsa.SetEncodedHash('hex', hash1)
         success = dsa.SignHash()
         hexSig=dsa.encodedSignature('hex')
         print("Signature:")
         print(hexSig)
         end_time1=time.time()-start_time1
         print ("Signature time:")
         print end_time1
         result1.append(float(end_time1))
         #verifikimi
         dsa2=chilkat.CkDsa()
         pemPublicKey = dsa2.loadText("dsa_pub.pem")
         success = dsa2.FromPublicPem(pemPublicKey)
         start_time2=time.time()
         success = dsa2.SetEncodedHash('hex',hash1)
         success = dsa2.SetEncodedSignature("hex",hexSig)
         success = dsa2.Verify()
         if (success != True):
             print(dsa2.lastErrorText())
         else:
             print("DSA Signature Verified!")
         end_time2=time.time() - start_time2

         result2.append(float(end_time2))
         print ("Verification time:")
         print end_time2
         print("")
    
p2=dsa1()
print("End of DSA")

class dash1:
    external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']

    app = dash.Dash(__name__, external_stylesheets=external_stylesheets)

    app.layout = html.Div(children=[
        html.H1(children='Speed Test'),

        html.Div(children='''
        
    '''),

   
    
    dcc.Graph(
        id='example-graph',
        figure={
            'data': [
                {'x': p.i, 'y': p.result, 'type': 'line', 'name': 'RSA Signature'},
                {'x': p2.j, 'y': p2.result1, 'type': 'line', 'name': 'DSA Signature'},
               
               
            ],
            'layout': {
                'title': 'RSA/DSA Signature '
            }
        }
    ),

    
    dcc.Graph(
        id='example-graph1',
        figure={
            'data': [
                {'x': p.i, 'y': p.resultt, 'type': 'line', 'name': 'RSA Verify'},
                {'x': p2.j, 'y': p2.result2, 'type': 'line', 'name': 'DSA Verify'}
               
            ],
            'layout': {
                'title': 'RSA/DSA Verify'
            }
            }
      )
])

    if __name__ == '__main__':
        app.run_server(debug=True)













