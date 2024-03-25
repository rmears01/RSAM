from flask import Flask, request
import requests, rsa, threading, json, logging

#simple rsa functions
def generate_keys():
    public_key, private_key = rsa.newkeys(1024)
    return [public_key,private_key]
def encrypt(message, public_key):
    return rsa.encrypt(message.encode(), public_key)
def decrypt(message, private_key):
    return rsa.decrypt(message, private_key).decode()

app = Flask(__name__)


def main():
    choice = input("generate new keyset? (y/n):")
    if choice.lower() == "y":
        keys = generate_keys()
        with open("public.pem", "wb") as file:
            file.write(keys[0].save_pkcs1("PEM"))
            file.close()
        with open("private.pem", "wb") as file:
            file.write(keys[1].save_pkcs1("PEM"))
            file.close()
    else:
        with open("public.pem", "rb") as file:
            public_key = rsa.PublicKey.load_pkcs1(file.read())
            file.close()
        with open("private.pem", "rb") as file:
            private_key = rsa.PrivateKey.load_pkcs1(file.read())
            file.close()

    server = input("url or ip of the recieving client:")
    while True:
        message = input("message to send:")
        public_key = rsa.PublicKey.load_pkcs1(requests.get(server + "/getKey").text)
        with open("message", "wb") as file:
            file.write(encrypt(message, public_key))
            file.close()
        files = {'file': open('message','rb')}
        requests.post(server + "/recv", files=files)

        


main = threading.Thread(target=main)
main.start()


@app.route('/getKey')
def getKey():
    with open("public.pem", "rb") as file:
        public_key = rsa.PublicKey.load_pkcs1(file.read())
        file.close()
    return public_key.save_pkcs1("PEM")

@app.route('/recv', methods=["POST"])
def recv():
    files = request.files["file"]
    files.save("message")
    with open("private.pem", "rb") as file:
        private_key = rsa.PrivateKey.load_pkcs1(file.read())
        file.close()
    with open("message", "rb") as file:
        message = decrypt(file.read(), private_key)
        file.close()
    
    with open(f"messages.log", "a") as file:
        file.write(message + "\n")
        file.close()
    return "success"

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=80)
