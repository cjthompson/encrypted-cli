#!/usr/bin/env node

'use strict';

const Kripke = require('kripke');
const version = require('./package').version;
const program = require('commander');
const fs = require('fs');
const readfile = require('fs').readFileSync;
const writefile = require('fs').writeFileSync;
const StringDecoder = require('string_decoder').StringDecoder;

function base64ToBinary (str) {
	if (typeof Buffer.from === 'function') {
		return Buffer.from(str, 'base64');
	} else {
		return new Buffer(str, 'base64');
	}
}

function encryptedContentsToBinary (str) {
	return str.split('$').map(function (s) {
    return base64ToBinary(s);
  });
}

function readBinaryFile (inputFile, cb) {
  const file = fs.createReadStream(inputFile);
  file.once('readable', function () {
    const results = [];
    let decode = [];
    let chunk;
    while (chunk = file.read(1)) {
      if (chunk[0] !== 0) {
        decode.push(chunk[0]);
      } else {
        if (decode.length) {
          results.push(new Buffer(decode).toString('base64'));
          decode = [];
        }
      }
    }
    cb(null, results.join('$'));
  });
}

program
	.version(version)
	.command('encrypt <file>')
	.description('Encrypt a file using a given key')
	.option('-k, --key <key>', 'Value used to derive the encryption key')
	.option('-h, --hmackey <hmackey>', 'Value used to derive the HMAC key')
	.option('-o, --outfile <outfile>', 'Destination file for the encrypted value')
	.action(function (file, options) {
		const k = new Kripke({ key: options.key, hmacKey: options.hmackey });
		try {
			const contents = readfile(file, 'utf8');
			k.encrypt(contents, function (err, result) {
        if (err) {
          console.log('Encryption error: ' + err.message);
        } else {
          try {
            if (options.outfile) {
              const file = fs.createWriteStream(options.outfile);
              encryptedContentsToBinary(result).forEach(function (v) {
                file.write(v);
                file.write(new Buffer([0]));
              });
              file.end(function () {
                console.log('File written');
              });
            } else {
              console.log('Result:');
              console.log(result);
            }
          } catch (e) {
            console.log('Error writing to the destination file: ' + options.outfile);
            console.log(e.message);
          }
        }
			});
		} catch (e) {
			console.log('Unable to open the file: ' + file);
			console.log(e.message);
		}
	});

program
	.command('decrypt <file>')
	.description('Decrypt a file using a given key')
	.option('-k, --key <key>', 'Value used to derive the encryption key')
	.option('-h, --hmackey <hmackey>', 'Value used to derive the HMAC key')
	.option('-o, --outfile <outfile>', 'Destination file for the encrypted value')
	.action(function (file, options) {
    readBinaryFile(file, function (err, contents) {
      if (err) { return console.log('Read error: ' + err.message); }
		  
      const k = new Kripke({ key: options.key, hmacKey: options.hmackey });
      k.decrypt(contents, function (err, result) {
        if (err) {
          console.log('Decryption error: ' + err.message);
        } else {
          try {
            if (options.outfile) {
              writefile(options.outfile, result);
            } else {
              console.log('Result:');
              console.log(result);
            }
          } catch (e) {
            console.log('Error writing to the destination file: ' + options.outfile);
            console.log(e.message);
          }
        }
      });
	  });
  });


program.parse(process.argv);

if (program.args.length === 0) {
	program.help();
}

