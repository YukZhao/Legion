;; a small demo

(import (lib hex core))


(lambda (args)
   (print
      (list->string 
         (foldr render null
            (interleave " "
               (map hex-encode args)))))
   1)

