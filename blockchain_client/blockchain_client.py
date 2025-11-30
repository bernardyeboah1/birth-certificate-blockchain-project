from flask import Flask, render_template, jsonify, request
from time import time
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
import binascii
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

class CertificateRequest:
    def __init__(self, hospital_public_key, hospital_private_key, child_name, date_of_birth, time_of_birth, obstetrician, place_of_birth, parent1_name, parent2_name, nurse_name, nurse_registraion_number):
        self.hospital_public_key = hospital_public_key
        self.hospital_private_key = hospital_private_key
        self.child_name = child_name
        self.date_of_birth = date_of_birth
        self.time_of_birth = time_of_birth
        self.obstetrician = obstetrician
        self.place_of_birth = place_of_birth
        self.parent1_name = parent1_name
        self.parent2_name = parent2_name
        self.nurse_name = nurse_name
        self.nurse_registraion_number = nurse_registraion_number

    def to_dict(self):
        return OrderedDict({
            "hospital_public_key": self.hospital_public_key,
            "child_name": self.child_name, 
            "date_of_birth": self.date_of_birth, 
            "time_of_birth" : self.time_of_birth,
            "obstetrician" : self.obstetrician,
            "place_of_birth": self.place_of_birth,
            "parent1_name": self.parent1_name,
            "parent2_name": self.parent2_name,
            "nurse_name" : self.nurse_name,
            "nurse_registraion_number": self.nurse_registraion_number
        })
    
    def sign_transaction(self):
        private_key = RSA.importKey(binascii.unhexlify(self.hospital_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str((self.to_dict())).encode("utf8"))
        return binascii.hexlify(signer.sign(h)).decode("ascii")

    
        





# init the node
app = Flask(__name__)

@app.route("/")
def index():
    return render_template("./index.html")


@app.route("/make/transaction")
def make_transaction():
    return render_template("./make_transaction.html")


@app.route("/generate/transaction", methods=["POST"])
def generate_transaction():
    hospital_public_key = request.form["hospital_public_key"]
    hospital_private_key = request.form["hospital_private_key"]
    child_name = request.form["child_name"]
    date_of_birth = request.form["date_of_birth"]
    time_of_birth= request.form["time_of_birth"]
    obstetrician= request.form["obstetrician"]
    place_of_birth = request.form["place_of_birth"]
    parent1_name = request.form["parent1_name"]
    parent2_name = request.form["parent2_name"]
    nurse_name = request.form["nurse_name"],
    nurse_registraion_number = request.form["nurse_registraion_number"]

    certificate = CertificateRequest(
        hospital_public_key=hospital_public_key,
        hospital_private_key=hospital_private_key,
        child_name=child_name,
        date_of_birth=date_of_birth,
        time_of_birth=time_of_birth,
        obstetrician=obstetrician,
        place_of_birth=place_of_birth,
        parent1_name=parent1_name,
        parent2_name=parent2_name,
        nurse_name=nurse_name,
        nurse_registraion_number=nurse_registraion_number
    )

    response = {"certificate":certificate.to_dict(), "signature":certificate.sign_transaction()}
    return jsonify(response),200



@app.route("/view/transactions")
def view_transaction():
    return render_template("./view_transactions.html")


@app.route("/wallet/new")
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key =  private_key.publickey()

    response = {
        "private_key": binascii.hexlify(private_key.exportKey(format("DER"))).decode("ascii"),
        "public_key": binascii.hexlify(public_key.exportKey(format("DER"))).decode("ascii")
    }

    return jsonify(response), 200


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser()

    parser.add_argument("-p", "--port", default = 8000, type = int, help = "port")
    args = parser.parse_args()
    port = args.port
    app.run(host = "127.0.0.1", port = port, debug = True)