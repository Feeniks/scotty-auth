
module Web.Scotty.Auth.Types where 

import Crypto.Cipher.AES
import qualified Data.ByteString.Char8 as B
import qualified Data.Text.Lazy as T

class Token t where 
    serialize :: t -> B.ByteString
    deserialize :: B.ByteString -> Maybe t

data Auth = Auth {
    authAES :: AES,
    authHeader :: T.Text
}

data AuthToken t = AuthToken {
    atExpiryUTC :: Int,
    atToken :: t
}



