
module Web.Scotty.Auth(
    Web.Scotty.Auth.Types.Token(..),
    createAuth, 
    setAuthToken,
    authRequired,
    authOptional
) where 

import Web.Scotty.Auth.Types
import Web.Scotty.Auth.Instances

import Control.Exception (SomeException, handle)
import Control.Monad.Trans
import Crypto.Cipher.AES
import Data.Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text.Lazy as T
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Word8
import Web.Scotty

createAuth :: String -> String -> Auth
createAuth hexkey authHeader = Auth aes (T.pack authHeader)
    where aes = initAES $ fst (B16.decode $ B.pack hexkey)

setAuthToken :: Token t => Auth -> Int -> t -> ActionM ()
setAuthToken auth expiryUTC tok = do 
    let headerName = authHeader auth
    let at16 = T.pack . B.unpack . encryptToken auth $ AuthToken expiryUTC tok
    addHeader headerName at16
   
authRequired :: Token t => Auth -> ActionM () -> (t -> ActionM ()) -> ActionM ()
authRequired auth authFailed f = do 
    mtok <- resolveTokenSafe auth
    maybe authFailed f mtok

authOptional :: Token t => Auth -> (Maybe t -> ActionM ()) -> ActionM ()   
authOptional auth f = resolveTokenSafe auth >>= f
    
resolveTokenSafe :: Token t => Auth -> ActionM (Maybe t)
resolveTokenSafe auth = do 
    tokH <- fmap (fmap $ B.pack . T.unpack) (header $ authHeader auth)
    liftIO $ handleSome (\_ -> return Nothing) (resolveToken auth tokH)
    
resolveToken :: Token t => Auth -> Maybe (B.ByteString) -> IO (Maybe t)
resolveToken auth tokH = maybe (return Nothing) resolveCheckExpiry (tokH >>= decryptToken auth)
    
resolveCheckExpiry :: Token t => AuthToken t -> IO (Maybe t)
resolveCheckExpiry (AuthToken e t) = do 
    tme <- liftIO $ fmap round getPOSIXTime
    case e > tme of 
        True -> return $ Just t
        False -> return Nothing

encryptToken :: Token t => Auth -> t -> B.ByteString
encryptToken auth t = B16.encode (encrypt (authAES auth) $ serialize t)

decryptToken :: Token t => Auth -> B.ByteString -> Maybe t
decryptToken auth s = decrypt (authAES auth) buf >>= deserialize 
	where (buf,_) = B16.decode s

encrypt :: AES -> B.ByteString -> B.ByteString
encrypt aes input = encryptECB aes $ BS.append (pad input) input
	where 
	drem = 16 - (mod (B.length input) 16)
	pad ix
		| drem == 16 = BS.pack $ [16] ++ replicate 15 0
		| otherwise = BS.pack $ [fromIntegral $ drem] ++ replicate (drem - 1) 0
		
decrypt :: AES -> B.ByteString -> Maybe B.ByteString
decrypt aes input 
	| mod (B.length input) 16 /= 0 = Nothing
	| otherwise = Just $ unpad (decryptECB aes input) 
	where 
	unpad ct = BS.drop (fromIntegral $ BS.head ct) ct

handleSome :: (SomeException -> IO a) -> IO a -> IO a
handleSome = handle



