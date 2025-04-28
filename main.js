const fs = require('fs');
const crypto = require('crypto');
const readlineSync = require('readline-sync');
const path = require('path');


// data folder
const dataPath = path.join(__dirname, 'data', 'passwords.enc');

const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const KEY_LENGTH = 32;
const ITERATIONS = 100000;
const ALGORITHM = 'aes-256-gcm';


// master password key generator
function deriveKey(password, salt) {
    return crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, 'sha512');
}

function encryptData(data, password) {
    const salt = crypto.randomBytes(SALT_LENGTH);
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = deriveKey(password, salt);

    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const tag = cipher.getAuthTag();

    return Buffer.concat([salt, iv, tag, encrypted]);
}

function decryptData(buffer, password) {
    const salt = buffer.slice(0, SALT_LENGTH);
    const iv = buffer.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const tag = buffer.slice(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + 16);
    const encrypted = buffer.slice(SALT_LENGTH + IV_LENGTH + 16);

    const key = deriveKey(password, salt);

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(encrypted, null, 'utf8');
    decrypted += decipher.final('utf8');

    return JSON.parse(decrypted);
}

function loadPasswords(password) {
    if (!fs.existsSync(dataPath)) return {};

    const encrypted = fs.readFileSync(dataPath);
    return decryptData(encrypted, password);
}

function savePasswords(data, password) {
    const encrypted = encryptData(data, password);
    fs.writeFileSync(dataPath, encrypted);
}

function main() {
    const masterPassword = readlineSync.question('Enter master password: ', { hideEchoBack: true });

    let passwords;
    try {
        passwords = loadPasswords(masterPassword);
    } catch (error) {
        console.error('Decryption error. Probably an invalid master password.');
        process.exit(1);
    }

    while (true) {
        console.log('\n1. Add password');
        console.log('2. Get password');
        console.log('3. Change password');
        console.log('4. Delete password');
        const choice = readlineSync.question('Select an action: ');

        if (choice === '1') {
            const service = readlineSync.question('Name of Service: ');
            const password = readlineSync.question('Password: ');
            passwords[service] = password;
            savePasswords(passwords, masterPassword);
            console.log('Password saved.');
        } else if (choice === '2') {
            const allservices = Object.keys(passwords);
            const index = readlineSync.keyInSelect(allservices, 'Select the service');
            if (passwords[allservices[index]]) {
                console.log(`Password for ${allservices[index]}: ${passwords[allservices[index]]}`);
            } else {
                console.log('Service not found.');
            }
        } else if (choice === '3') {
            const allservices = Object.keys(passwords);
            const index = readlineSync.keyInSelect(allservices, 'Select the service');
            const password = readlineSync.question('New password: ');

            if (readlineSync.keyInYN(`Are you sure you want to change password to ${allservices[index]}\n`)){
                passwords[allservices[index]] = password;
                savePasswords(passwords, masterPassword);
                console.log('Password changed.');
            }
            else {
                console.log('Password change cancelled')
            }
        } else if (choice === '4') {
            const allservices = Object.keys(passwords);
            const index = readlineSync.keyInSelect(allservices, 'Select the service');

            if (passwords[allservices[index]]) {
                if (readlineSync.keyInYN(`Are you sure you want to delete password to ${allservices[index]}\n`)){
                    delete passwords[allservices[index]];
                    savePasswords(passwords, masterPassword);
                    console.log('Password deleted.');
                }
                else {
                    console.log('Password deletion cancelled')
                }
            } else {
                console.log('Service not found');
            }
        } else {
            console.log('unknown command');
        }
    }
}

main();
