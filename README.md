# DECRYPTION API

## How To Run

go run .

## APIs

All APIs that can accept a body will assume that that body is JSON.

All examples assume you run on localhost

### Decrypt Json

**URL** : `{{local}}/api/v1/ref-codes/pos/:posID`

**Method** : POST
 
**Body** : 

Please note: I am just sending the key for a future implementation with RSA. (AES Key will be encrypted with RSA soon)

```json
{
    "Data" : "stringToDecrypt",
    "Key"  : "aesKey"
}
```


#### Success Response

**Code** : `200 OK`

The response would be a json





