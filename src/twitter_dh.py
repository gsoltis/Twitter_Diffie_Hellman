'''
Created on Nov 19, 2010

@author: Greg Soltis (gsoltis@gmail.com)
'''

from Crypto.Cipher import AES
from Crypto.Util.randpool import RandomPool
from Crypto.Util.number import getPrime, getRandomNumber
from base64 import b64encode, b64decode
import binascii
from functools import partial
import os
import math
from threading import Condition
from optparse import OptionParser 
import time

from tweepy import OAuthHandler, TweepError, Stream, StreamListener, API

PRIME_BITS = 300
API_KEY = 'your api key'
CONSUMER_KEY = API_KEY
CONSUMER_SECRET = 'your consumer secret'
USER_AGENT = 'Your user agent'

TWEET_LEN = 140
MAX_CHUNKS = 99

class Twitter_DH(object):
    
    def __init__(self, alice, bob):
        self.alice = alice
        self.bob = bob
        self.key = None
        self.twitter = None
        self.api = None
        self.stream = None
        self.listener = None
        self.my_id = None
        self.other_id = None
        self.lock = Condition()
        self.should_run = True
        self.is_bob = False
        self.get_key_func = None
    
    def _get_aes(self, key):
        return AES.new(key, AES.MODE_CBC)
    
    def modExp(self, a, b, m) :
        """
        Computes a to the power b, modulo m, using binary exponentiation
        this function taken from source at: http://numericalrecipes.wordpress.com/tag/modular-arithmetic/
        """
        a %= m
        ret = None
        if b == 0:
            ret = 1
        elif b % 2:
            ret = a * self.modExp(a, b - 1, m)
        else :
            ret = self.modExp(a, b // 2 , m)
            ret *= ret
        return ret % m

    def _get_random_pool(self):
        pool = RandomPool()
        pool.randomize()
        return pool

    def _get_dh_secret(self, pool):
        return getRandomNumber(16, pool.get_bytes)
    
    def write_twitter_message(self, dst, msg):
        print 'sending: %s' % msg
        dst = '@' + dst
        dst_len = len(dst)
        chunk_size = TWEET_LEN - (dst_len + 1 + 2 + 1 + 2 + 1)  # 1 for space, 2 for num chunks, 1 for space, 2 for index, 1 for space
        msg_len = len(msg)
        num_chunks = int(math.ceil(float(msg_len) / float(chunk_size)))
        assert num_chunks * chunk_size >= msg_len
        assert num_chunks <= MAX_CHUNKS
        done = False
        i = 0
        while not done:
            offset = i * chunk_size
            end_point = min([offset + chunk_size, msg_len])
            if end_point == msg_len:
                done = True
            tweet = '%s %02d %02d %s' % (dst, num_chunks, i, msg[offset:end_point])
            i = i + 1
            self.api.update_status(tweet)
            time.sleep(0.5)
    
    def _write_encrypted_twitter_message(self, dst, plain_text):
        aes = self._get_aes(self.key)
        text_len = len(plain_text)
        mod = 16 - (text_len % 16)
        if mod != 0:
            plain_text = plain_text.ljust(text_len + mod, '\0')
        cipher_text = b64encode(aes.encrypt(plain_text))
        self.write_twitter_message(dst, cipher_text)

    def _decrypt_twitter_message(self, cipher_text):
        cipher_text = b64decode(cipher_text)
        aes = self._get_aes(self.key)
        plain_text = aes.decrypt(cipher_text).strip('\0')
        print plain_text
    
    def _dh_key(self, secret, prime, public):
        '''
        key = public ^ secret mod prime
        '''
        key = self.modExp(public, secret, prime)
        key = hex(key)
        key = key[2:-1]
        key = binascii.unhexlify(key[:64])
        self.key = key
    
    def _bob_dh_values(self, A, g, p):
        pool = self._get_random_pool()
        b = self._get_dh_secret(pool)
        B = self.modExp(g, b, p)
        return (b, B)
    
    def _do_dh_bob(self, A, g, p):
        (b, B) = self._bob_dh_values(A, g, p)
        return (B, partial(self._dh_key, b, p))
    
    
    def _alice_dh_values(self):
        pool = self._get_random_pool()
        g = 5
        p = getPrime(PRIME_BITS, pool.get_bytes)
        a = self._get_dh_secret(pool)
        A = self.modExp(g, a, p)
        return a, g, p, A
    
    def _do_dh_alice(self):
        (a, g, p, A) = self._alice_dh_values()
        return (A, g, p, partial(self._dh_key, a, p))

    def _get_twitter_access(self, username):
        auth = OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
        url = auth.get_authorization_url()
        print 'Go here: %s and enter the corresponding PIN' % url
        pin = raw_input('PIN:')
        auth.get_access_token(pin)
        return (auth.access_token.key, auth.access_token.secret)

    def _setup_oauth(self, username):
        dir = os.path.dirname(__file__)
        username_file = os.path.join(dir, '%s.twitter' % username)
        if not os.path.exists(username_file):
            (access_key, access_secret) = self._get_twitter_access(username)
            f = open(username_file, 'w')
            f.write('%s\n%s' % (access_key, access_secret))
            f.close()
        f = open(username_file, 'r')
        data = f.read()
        f.close()
        parts = data.split('\n')
        access_key = parts[0]
        access_secret = parts[1]
        auth = OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
        auth.set_access_token(access_key, access_secret)
        return auth

    def _setup_twitter(self, username):
        self.twitter = self._setup_oauth(username)
        self.api = API(self.twitter)
        self.my_id = self.api.me().id
    
    class Listener(StreamListener):
    
        def __init__(self, api, my_user_id, cv):
            super(Twitter_DH.Listener, self).__init__(api)
            self.my_user_id = my_user_id
            self.buffer = None
            self.queue = []
            self.cv = cv
            self.timed_out = False
        
        def _process_text(self, text):
            parts = text.split(' ') # note: change upper layer delimiter
            total_tweets = int(parts[1])
            index = int(parts[2])
            msg = parts[3]
            assert len(parts) == 4
            if not self.buffer:
                self.buffer = [None] * total_tweets
            self.buffer[index] = msg
            try:
                self.buffer.index(None)
                return True
            except ValueError:
                # we've filled the buffer
                to_fill = ''.join(self.buffer)
                self.cv.acquire()
                self.queue.append(to_fill)
                self.buffer = ''
                self.cv.notify()
                self.cv.release()
        
        def on_status(self, status):
            if hasattr(status, 'entities'):
                entities = status.entities
                if 'user_mentions' in entities:
                    # Make sure it's from the user we expect
                    user_mentions = entities['user_mentions']
                    for mention in user_mentions:
                        if mention['id'] == self.my_user_id:
                            return self._process_text(status.text)
        
        def on_timeout(self):
            self.cv.acquire()
            self.timed_out = True
            self.cv.notify()
            self.cv.release()
            return False
            
        def on_error(self, status):
            print 'Got error status: %s' % str(status)
            return False
                  
    def _run_loop(self):
        self.lock.acquire()
        self._listen()
        if not self.is_bob:
            (A, g, p, self.get_key_func) = self._do_dh_alice()
            msg = '%s:%s:%s' % (str(A), str(g), str(p))
            self.write_twitter_message(self.bob, msg)
        while self.should_run:
            if len(self.listener.queue) == 0:
                self.lock.wait()
            if self.listener.timed_out:
                self.should_run = False
                print 'stopping for timeout'
            else:
                msg = self.listener.queue.pop(0)
                if self.key:
                    self._decrypt_twitter_message(msg)
                    self.should_run = False
                else:
                    if self.is_bob:
                        parts = map(long, msg.strip().split(':'))
                        (B, self.get_key_func) = self._do_dh_bob(parts[0], parts[1], parts[2])
                        self.get_key_func(parts[0])
                        self.write_twitter_message(self.alice, str(B))
                    else:
                        B = long(msg.strip())
                        self.get_key_func(B)
                        self._write_encrypted_twitter_message(self.bob, 'secret twitter message')
                        self.should_run = False
                        
            self.lock.release()
            if self.should_run:
                self.lock.acquire()
    
    def _listen(self):
        self.listener = Twitter_DH.Listener(self.api, self.my_id, self.lock)
        self.stream = Stream(self.twitter, self.listener, timeout=15, headers={'User-Agent': USER_AGENT})
        self.stream.filter(follow=[self.other_id], async=True)
    
    def run_alice(self):
        self._setup_twitter(self.alice)
        self.other_id = self.api.get_user(bob).id
        self._run_loop()

    def run_bob(self):
        self.is_bob = True
        self._setup_twitter(self.bob)
        self.other_id = self.api.get_user(self.alice).id
        self._run_loop()

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-a', '--alice', dest='alice', help='Twitter handle for Alice')
    parser.add_option('-b', '--bob', dest='bob', help='Twitter handle for Bob')
    parser.add_option('-B', action='store_true', dest='use_bob', default=False, help='Set this flag if you are acting as Bob')
   
    (options, args) = parser.parse_args()
    alice = options.alice
    bob = options.bob
    twitter_dh = Twitter_DH(alice, bob)
    if options.use_bob:
        twitter_dh.run_bob()
    else:
        twitter_dh.run_alice()
    print 'done'
