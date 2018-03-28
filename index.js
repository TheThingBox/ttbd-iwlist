// extracted with substacks blessing from https://github.com/substack/virus-copter/blob/master/lib/iw.js

var exec = require('ttbd-exec')
var EventEmitter = require('events').EventEmitter;
var http = require('http')
var dns = require('dns')

module.exports = function (iface, exec_option) {
    return new IW(iface, exec_option);
};

function IW (iface, exec_option) {
    if (!(this instanceof IW)) return new IW(iface, exec_option);
    this.iface = iface;
    this.exec_option = exec_option || {} ;
}

IW.prototype = new EventEmitter;

IW.prototype.associated = function(cb) {
    exec({cmd: `iwconfig ${this.iface}`}, this.exec_option, function(err, stdout, stderr) {
        if (err) return cb(err)
        try {
            var status = stdout.match(/Access Point: (.*)\n/)[1]
            if (status.match(/Not-Associated/)) return cb(false, false)
            cb(false, true)
        } catch(e) {
            cb(e)
        }
    })
}

IW.prototype.online = function(cb) {
  dns.lookup('www.google.com', function(err, addresses) {
    if (err) return cb(err)
    return cb(false)
  })
}

IW.prototype.disconnect = function(cb) {
    exec({cmd: `iwconfig ${this.iface} essid off`}, cb)
}

IW.prototype.scan = function (cb) {
    var ap = []
    var current = null;

    exec({cmd: `iwlist ${this.iface} scan`}, this.exec_option, function(err, stdout, stderr) {
        if(err){
            cb(err, stderr)
            return
        }
        var lines = stdout.split('\n')
        for(var index in lines){
            parseLine(lines[index])
        }

        ap.sort(function(a, b) {
            var x = a['signal']; var y = b['signal'];
            return ((x < y) ? -1 : ((x > y) ? 1 : 0));
        }).reverse()
        cb(null, ap);
    })
        
    function parseLine(line) {
        var m;
        
        if (m = /^\s+Cell \d+ - Address: (\S+)/.exec(line)) {
            current = { address : m[1] };
            ap.push(current);
            return;
        }
        if (!current) return;
        
        if (m = /^\s+ESSID:"(.+)"/.exec(line)) {
            current.essid = m[1];
        }
        if (m = /^\s+Encryption key:(.+)/.exec(line)) {
            current.encrypted = m[1] !== 'off';
        }
        if (m = /Signal level=(.+?)\//.exec(line)) {
          current.signal = +m[1]
        }
    }
};

IW.prototype.connect = function (ap, cb) {
    var self = this;
    var returned = false
    if (typeof ap === 'string') ap = { essid : ap };
    
    exec({cmd: `iwconfig ${self.iface} essid ${ap.essid}`}, this.exec_option, function(err, stdout, stderr) {
      if (stderr !== '') {
        returned = true
        return cb(stderr)
      }
    })
    
    var iv = setInterval(function (err, stdout, stderr) {
        exec({cmd: `iwconfig ${self.iface}`}, this.exec_option, function(err, stdout, stderr) {
            var m;
            if (m = /ESSID:"(.+?)"/.exec(stdout)) {
                if (m[1] === ap.essid) {
                    clearInterval(iv);
                    clearTimeout(to);
                    if (!returned) cb(null);
                }
            }
        });
    }, 1000);
    
    var to = setTimeout(function () {
        clearInterval(iv);
        if (!returned) cb('connection to ' + ap + ' timed out');
    }, 20 * 1000);
};
