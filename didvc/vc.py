from pyld import jsonld
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from multibase import encode, decode
from jwcrypto import jwk, jwe, jwt
import json
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from datetime import datetime
import base58, base64

import didvc
from didvc.signatures import Ed25519Signature2020
from didvc.signatures import Ed25519Signature2018


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


def sign(credentials, key, keyid, proofType = "Ed25519Signature2020"):

    # Remove the proof if any
    # Should we raise an error if there's a proof already ?
    credentials_to_sign = credentials.copy()
    credentials_to_sign.pop('proof', None)

    #
    # Hash canonized credentials
    #
    doc_hash = hash_jsonld(credentials_to_sign)
    #print(len(doc_hash)) # Should be 32


    #
    # Hash proof
    #

    # Define the proof template
    proof = {
        "type": proofType,
        "proofPurpose": "assertionMethod",
        "verificationMethod": keyid,
        "created": datetime.now().isoformat(sep='T',timespec='auto')
    }
    # Hash the proof options
    proof_hash = hash_proof_options(proof, credentials_to_sign["@context"])

    # convert the JWK into a PEM representation, required by cryptography.hazmat
    keypair = jwk.JWK.from_json(json.dumps(key))
    pkcs8Pem = keypair.export_to_pem(private_key=True, password=None)

    # Load private key using cryptography.hazmat.primitives
    private_key = load_pem_private_key(pkcs8Pem, password=None)
    #private_key = ed25519.Ed25519PrivateKey.from_private_bytes(privateBytes)


    if proofType == "Ed25519Signature2020":
        proofValue = Ed25519Signature2020.create_proof_signature(doc_hash, proof_hash, lambda bytes: private_key.sign(bytes))

        proof['proofValue'] = proofValue
    elif proofType == "Ed25519Signature2018":
        proof['jws'] = Ed25519Signature2018.create_proof_signature(doc_hash, proof_hash, lambda bytes: private_key.sign(bytes))
    else:
        raise Exception("Proof type not supported: "+proofType)


    credentials_to_sign['proof'] = proof

    return credentials_to_sign


async def verify(credentials):
    proof = credentials['proof']
    methodId = proof['verificationMethod']
    did = methodId.split('#')[0]
    diddoc = await didvc.resolve(did)

    method = next((method for method in diddoc['verificationMethod'] if method['id'] == methodId), None)
    if 'publicKeyJwk' in method:
        publicKeyJwk = method['publicKeyJwk']
    elif 'publicKeyBase58' in method:
        publicKey58 = method['publicKeyBase58']
        publicKeyBytes = base58.b58decode(publicKey58)
        publicKey64 = base64.urlsafe_b64encode(publicKeyBytes).decode().strip('=')
        publicKeyJwk = {'crv': 'Ed25519', 'kty': 'OKP', 'x': publicKey64}
    else:
        raise Exception("Require publicKeyJwk or publicKeyBase58")

    return verify_with_key(credentials, publicKeyJwk)

def verify_with_key(credentials, key):

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

    # convert the JWK into a PEM representation, required by cryptography.hazmat
    keypair = jwk.JWK.from_json(json.dumps(key))
    pkcs8Pem = keypair.export_to_pem(private_key=False, password=None)

    # Load private key using cryptography.hazmat.primitives
    public_key = load_pem_public_key(pkcs8Pem)


    proof_type = proof['type']
    if proof_type == "Ed25519Signature2020":
        Ed25519Signature2020.verify_proof(doc_hash, proof_hash, proof, lambda signature, data: public_key.verify(signature, data))
    elif proof_type == "Ed25519Signature2018":
        Ed25519Signature2018.verify_proof(doc_hash, proof_hash, proof, lambda signature, data: public_key.verify(signature, data))
    else:
        raise Exception("Proof type not supported: " + proof_type)
