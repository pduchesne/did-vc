from pyld import jsonld
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from multibase import encode, decode
from jwcrypto import jwk, jwe, jwt
import json
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from datetime import datetime
import base58


# Implemented following https://grotto-networking.com/blog/posts/jsonldProofs.html and
# https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-rdfc-2022

def hash_jsonld(doc):
    # Canonize the document
    proof_canon = jsonld.normalize(
        doc, {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})

    temp_digest = hashes.Hash(hashes.SHA256())
    temp_digest.update(proof_canon.encode('utf8'))
    hash = temp_digest.finalize()

    return hash

def hash_proof_options(proof, context):
    # Make a copy of proof and remove signature fields
    reduced_proof = proof.copy()
    del_stuff = ["jws", "signatureValue", "proofValue"]
    for del_thing in del_stuff:
        if del_thing in reduced_proof:
            del reduced_proof[del_thing]

    # Add in the JSON-LD context. This should be the same context as that of the embedding VC
    if context:
        reduced_proof["@context"] = context
    else:
        # put a default context
        reduced_proof["@context"] = [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ]

    proof_hash = hash_jsonld(reduced_proof)

    return proof_hash


def sign(credentials, key, keyid):

    #
    # Hash canonized credentials
    #
    doc_hash = hash_jsonld(credentials)
    #print(len(doc_hash)) # Should be 32


    #
    # Hash proof
    #

    # Define the proof template
    proof = {
        "type": "Ed25519Signature2020",
        "created": datetime.now().isoformat(sep='T',timespec='auto'),
        "verificationMethod": keyid,
        "proofPurpose": "assertionMethod",
        "proofValue": None
    }
    # Hash the proof options
    proof_hash = hash_proof_options(proof, credentials["@context"])


    # The hash to sign is the concatenation of the proof hash and the document hash,
    # as per https://www.w3.org/TR/vc-di-eddsa/#hashing-ed25519signature2020
    combined_hash = proof_hash + doc_hash


    #
    # Sign the hash
    #

    # convert the JWK into a PEM representation, required by cryptography.hazmat
    keypair = jwk.JWK.from_json(json.dumps(key))
    pkcs8Pem = keypair.export_to_pem(private_key=True, password=None)

    # Load private key using cryptography.hazmat.primitives
    private_key = load_pem_private_key(pkcs8Pem, password=None)
    #private_key = ed25519.Ed25519PrivateKey.from_private_bytes(privateBytes)

    # Sign the hash
    proofbytes = private_key.sign(combined_hash)
    #print(f"Length of proof signature: {len(proofbytes)}")

    ## is base58 the correct encoding ?
    proofValue = base58.b58encode(proofbytes) # encode(data=proofbytes, encoding='base64')


    #
    # Add the signature to the proof
    #
    proof['proofValue'] = proofValue.decode()

    return proof


def verify(credentials, key):

    #
    # Split the credentials into credentials_without_proof and proof
    #

    credentials_without_proof = credentials.copy()
    proof = credentials_without_proof.pop('proof')

    #
    # Hash canonized credentials
    #
    doc_hash = hash_jsonld(credentials_without_proof)

    #
    # Hash proof
    #
    # Hash the proof options
    proof_hash = hash_proof_options(proof, credentials["@context"])


    # The hash to sign is the concatenation of the proof hash and the document hash,
    # as per https://www.w3.org/TR/vc-di-eddsa/#hashing-ed25519signature2020
    combined_hash = proof_hash + doc_hash


    #
    # Verify the hash
    #

    # convert the JWK into a PEM representation, required by cryptography.hazmat
    keypair = jwk.JWK.from_json(json.dumps(key))
    pkcs8Pem = keypair.export_to_pem(private_key=False, password=None)

    # Load private key using cryptography.hazmat.primitives
    public_key = load_pem_public_key(pkcs8Pem)


    # Extract signature bytes
    proofbytes = base58.b58decode(proof['proofValue'])

    # Verify against the hash
    public_key.verify(proofbytes, combined_hash)
