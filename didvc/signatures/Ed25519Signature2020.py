import base58

def create_proof_signature(doc_hash, proof_hash, sign_fun):

    # The hash to sign is the concatenation of the proof hash and the document hash,
    # as per https://www.w3.org/TR/vc-di-eddsa/#hashing-ed25519signature2020
    combined_hash = proof_hash + doc_hash

    # Sign the hash
    proofbytes = sign_fun(combined_hash)
    #print(f"Length of proof signature: {len(proofbytes)}")

    ## is base58 the correct encoding ?
    proofValue = base58.b58encode(proofbytes) # encode(data=proofbytes, encoding='base64')

    return proofValue.decode()


def verify_proof(doc_hash, proof_hash, proof, verify_fun):
    # The hash to sign is the concatenation of the proof hash and the document hash,
    # as per https://www.w3.org/TR/vc-di-eddsa/#hashing-ed25519signature2020
    combined_hash = proof_hash + doc_hash

    # Extract signature bytes
    proofbytes = base58.b58decode(proof['proofValue'])

    # Verify against the hash
    verify_fun(proofbytes, combined_hash)