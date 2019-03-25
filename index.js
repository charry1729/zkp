const { encryptWithProof, verifyProof } = require('paillier-in-set-zkp')
const paillier = require('paillier-js')
const assert = require('assert')
const bits = 512

const {publicKey, privateKey} = paillier.generateRandomKeys(bits)
const validCertids = [30]
const secretcertid =30
const [cipher, proof] = encryptWithProof(publicKey, secretcertid, validCertids, bits)

// Transmit cipher, proof and publicKey

const result = verifyProof(publicKey, cipher, proof, validCertids, bits) // true

//validCertids = validCerts

//testing 

const settings = [32,256,512,1024]
settings.forEach(bits => {
  {
    const {publicKey, privateKey} = paillier.generateRandomKeys(bits)
    const validCerts = [42,666,13]
    const certid = 42
    const [cipher, proof] = encryptWithProof(publicKey, certid, validCerts, bits)
    
    const result = verifyProof(publicKey, cipher, proof, validCerts)
    assert.equal(privateKey.decrypt(cipher), certid)
    assert(result)

    console.log("publicKey : "+publicKey)
    console.log("privateKey : "+privateKey)
    console.log("cipher : "+cipher)
    console.log("proof : "+proof)
    console.log("result : "+result)
    console.log("resust1")
  }
  {
    const {publicKey, privateKey} = paillier.generateRandomKeys(bits)
    const validCerts = [42,666,13]
    const evilcertid = 43
    const [cipher, proof] = encryptWithProof(publicKey, evilcertid, validCerts, bits)
    const result = verifyProof(publicKey, cipher, proof, validCerts)
    assert.equal(privateKey.decrypt(cipher), evilcertid)
    assert(!result)
    console.log("publicKey : "+publicKey)
console.log("privateKey : "+privateKey)
console.log("cipher : "+cipher)
console.log("proof : "+proof)
console.log("result : "+result)
console.log("resust2")

  }
})

