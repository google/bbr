" Vim syntax file
" Language:  Packetdrill
" Maintainer:  Barath Raghavan <barath@google.com>
" Last Change:  2013 Jul 27

" Quit when a (custom) syntax file was already loaded
if exists("b:current_syntax")
  finish
endif

let s:cpo_save = &cpo
set cpo&vim

syn keyword     pKeyword      sa_family sin_port sin_addr msg_name msg_iov msg_flags fd events revents htons icmp udp inet_addr ack eol ecr mss mtu nop sack sackOK TS FO FOEXP val win wscale ect01 ect0 ect1 noecn ce
syn keyword     pConstant     AF_INET AF_INET6 AF_PACKET PF_INET PF_INET6 SOCK_RAW SOCK_STREAM SOCK_DGRAM IPPROTO_RAW IPPROTO_IP IPPROTO_IPV6 IPPROTO_ICMP IPPROTO_TCP IPPROTO_UDP SOL_SOCKET SOL_IP SOL_IPV6 SOL_TCP SOL_UDP SO_ACCEPTCONN SO_ATTACH_FILTER SO_BINDTODEVICE SO_BROADCAST SO_BSDCOMPAT SO_DEBUG SO_DETACH_FILTER SO_DONTROUTE SO_ERROR SO_KEEPALIVE SO_LINGER SO_NO_CHECK SO_OOBINLINE SO_PASSCRED SO_PEERCRED SO_PEERNAME SO_PEERSEC SO_PRIORITY SO_RCVBUF SO_RCVLOWAT SO_RCVTIMEO SO_REUSEADDR SO_REUSEPORT SO_SECURITY_AUTHENTICATION SO_SECURITY_ENCRYPTION_NETWORK SO_SECURITY_ENCRYPTION_TRANSPORT SO_SNDBUF SO_SNDLOWAT SO_SNDTIMEO SO_TIMESTAMP SO_TYPE SO_MAX_PACING_RATE SO_ZEROCOPY IP_TOS IP_MTU_DISCOVER IP_PMTUDISC_WANT IP_PMTUDISC_DONT IP_PMTUDISC_DO IP_PMTUDISC_PROBE IP_MTU IPV6_MTU TCP_NODELAY TCP_MAXSEG TCP_CORK TCP_KEEPIDLE TCP_KEEPINTVL TCP_KEEPCNT TCP_SYNCNT TCP_LINGER2 TCP_DEFER_ACCEPT TCP_INFO TCP_QUICKACK TCP_CONGESTION TCP_MD5SIG TCP_COOKIE_TRANSACTIONS TCP_THIN_LINEAR_TIMEOUTS TCP_THIN_DUPACK TCP_USER_TIMEOUT TCP_CWND TCP_SAVE_SYN TCP_SAVED_SYN TCP_FASTOPEN TCP_MULTIPLE_CONNECTIONS
syn keyword     pConstant     O_RDONLY O_WRONLY O_RDWR O_ACCMODE O_CREAT O_EXCL O_NOCTTY O_TRUNC O_APPEND O_NONBLOCK F_DUPFD F_GETFD F_SETFD F_GETFL F_SETFL F_GETLK F_SETLK F_SETLKW F_GETOWN F_SETOWN F_SETSIG F_GETSIG F_GETOWN F_SETOWN F_SETLK F_SETLKW F_GETLK F_SETLK64 F_SETLKW64 F_GETLK64 F_SETLEASE F_GETLEASE F_NOTIFY F_DUPFD_CLOEXEC FD_CLOEXEC LOCK_SH LOCK_EX LOCK_NB LOCK_UN F_RDLCK F_WRLCK F_UNLCK F_EXLCK F_SHLCK SEEK_SET SEEK_CUR SEEK_END MSG_OOB MSG_DONTROUTE MSG_PEEK MSG_CTRUNC MSG_PROXY MSG_EOR MSG_WAITALL MSG_TRUNC MSG_CTRUNC MSG_ERRQUEUE MSG_DONTWAIT MSG_CONFIRM MSG_FIN MSG_SYN MSG_RST MSG_NOSIGNAL MSG_MORE MSG_CMSG_CLOEXEC MSG_FASTOPEN MSG_ZEROCOPY SIOCINQ FIONREAD POLLIN POLLPRI POLLOUT POLLRDNORM POLLRDBAND POLLWRNORM POLLWRBAND POLLMSG POLLREMOVE POLLRDHUP POLLERR POLLHUP POLLNVAL EPERM ENOENT ESRCH EINTR EIO ENXIO E2BIG ENOEXEC EBADF ECHILD EAGAIN ENOMEM EACCES EFAULT ENOTBLK EBUSY EEXIST EXDEV ENODEV ENOTDIR EISDIR EINVAL ENFILE EMFILE ENOTTY ETXTBSY EFBIG ENOSPC ESPIPE EROFS EMLINK EPIPE EDOM ERANGE EDEADLK ENAMETOOLONG ENOLCK ENOSYS ENOTEMPTY ELOOP EWOULDBLOCK ENOMSG EIDRM ECHRNG EL2NSYNC EL3HLT EL3RST ELNRNG EUNATCH ENOCSI EL2HLT EBADE EBADR EXFULL ENOANO EBADRQC EBADSLT EDEADLOCK EBFONT ENOSTR ENODATA ETIME ENOSR ENONET ENOPKG EREMOTE ENOLINK EADV ESRMNT ECOMM EPROTO EMULTIHOP EDOTDOT EBADMSG EOVERFLOW ENOTUNIQ EBADFD EREMCHG ELIBACC ELIBBAD ELIBSCN ELIBMAX ELIBEXEC EILSEQ ERESTART ESTRPIPE EUSERS ENOTSOCK EDESTADDRREQ EMSGSIZE EPROTOTYPE ENOPROTOOPT EPROTONOSUPPORT ESOCKTNOSUPPORT EOPNOTSUPP EPFNOSUPPORT EAFNOSUPPORT EADDRINUSE EADDRNOTAVAIL ENETDOWN ENETUNREACH ENETRESET ECONNABORTED ECONNRESET ENOBUFS EISCONN ENOTCONN ESHUTDOWN ETOOMANYREFS ETIMEDOUT ECONNREFUSED EHOSTDOWN EHOSTUNREACH EALREADY EINPROGRESS ESTALE EUCLEAN ENOTNAM ENAVAIL EISNAM EREMOTEIO EDQUOT ENOMEDIUM EMEDIUMTYPE ECANCELED ENOKEY EKEYEXPIRED EKEYREVOKED EKEYREJECTED EOWNERDEAD ENOTRECOVERABLE ERFKILL POLLIN POLLPRI POLLOUT POLLRDNORM POLLRDBAND POLLWRNORM POLLWRBAND POLLMSG POLLREMOVE POLLRDHUP POLLERR POLLHUP POLLNVAL
syn keyword  pSyscall        accept bind close connect fcntl getsockopt ioctl listen poll read readv recv recvfrom recvmsg send sendmsg sendto setsockopt shutdown socket write writev
syn keyword  pPythonCmds     contained assert print
syn region   pPython         start='%{' end='}%' contains=pPythonCmds
syn keyword  pShellCmds      contained sysctl
syn region   pShell          start='`' end='`' contains=pShellCmds
syn keyword  pEllipsis       '...'
syn match    pInputPkt       "\s\+\zs<\ze\s\+"
syn match    pOutputPkt      "\s\+\zs>\ze\s\+"

" Below is stuff inherited from C, suitably modified.
" String and Character constants
" Highlight special characters (those which have a backslash) differently
syn match    cSpecial        display contained "\\\(x\x\+\|\o\{1,3}\|.\|$\)"
syn match    cFormat         display "%\(\d\+\$\)\=[-+' #0*]*\(\d*\|\*\|\*\d\+\$\)\(\.\(\d*\|\*\|\*\d\+\$\)\)\=\([hlLjzt]\|ll\|hh\)\=\([aAbdiuoxXDOUfFeEgGcCsSpn]\|\[\^\=.[^]]*\]\)" contained
syn match    cFormat         display "%%" contained
syn region   cString         start=+L\="+ skip=+\\\\\|\\"+ end=+"+ contains=cSpecial,cFormat,@Spell
" cCppString: same as cString, but ends at end of line
syn region   cCppString      start=+L\="+ skip=+\\\\\|\\"\|\\$+ excludenl end=+"+ end='$' contains=cSpecial,cFormat,@Spell

" This should be before cErrInParen to avoid problems with #define ({ xxx })
syn match    cCurlyError     "}"
syn region   cBlock          start="{" end="}" contains=ALLBUT,cBadBlock,cCurlyError,@cParenGroup,cErrInParen,cCppParen,cErrInBracket,cCppBracket,cCppString,@Spell fold

"catch errors caused by wrong parenthesis and brackets
" also accept <% for {, %> for }, <: for [ and :> for ] (C99)
" But avoid matching <::.
syn cluster  cParenGroup     contains=cParenError,cSpecial,cCommentSkip,cCommentString,cComment2String,@cCommentGroup,cCommentStartError,cUserCont,cBitField,cOctalZero,@cCppOutInGroup,cFormat,cNumber,cFloat,cOctal,cOctalError,cNumbersCom
syn region   cParen          transparent start='(' end=')' end='}'me=s-1 contains=ALLBUT,@cParenGroup,cCppParen,cErrInBracket,cCppBracket,cCppString,@Spell
" cCppParen: same as cParen but ends at end-of-line; used in cDefine
syn region   cCppParen       transparent start='(' skip='\\$' excludenl end=')' end='$' contained contains=ALLBUT,@cParenGroup,cErrInBracket,cParen,cBracket,cString,@Spell
syn match    cParenError     display "[\])]"
"syn match  cErrInParen  display contained "[\]{}]\|<%\|%>"
syn region   cBracket        transparent start='\[\|<::\@!' end=']\|:>' end='}'me=s-1 contains=ALLBUT,@cParenGroup,cErrInParen,cCppParen,cCppBracket,cCppString,@Spell
" cCppBracket: same as cParen but ends at end-of-line; used in cDefine
syn region   cCppBracket     transparent start='\[\|<::\@!' skip='\\$' excludenl end=']\|:>' end='$' contained contains=ALLBUT,@cParenGroup,cErrInParen,cParen,cBracket,cString,@Spell
"syn match  cErrInBracket  display contained "[);{}]\|<%\|%>"

"integer number, or floating point number without a dot and with "f".
syn case ignore
syn match    cNumbers        display transparent "\<\d\|\.\d" contains=cNumber,cFloat,cOctalError,cOctal
" Same, but without octal error (for comments)
syn match    cNumbersCom     display contained transparent "\<\d\|\.\d" contains=cNumber,cFloat,cOctal
syn match    cNumber         display contained "\d\+\(u\=l\{0,2}\|ll\=u\)\>"
"hex number
syn match    cNumber         display contained "0x\x\+\(u\=l\{0,2}\|ll\=u\)\>"
" Flag the first zero of an octal number as something special
syn match    cOctal          display contained "0\o\+\(u\=l\{0,2}\|ll\=u\)\>" contains=cOctalZero
syn match    cOctalZero      display contained "\<0"
syn match    cFloat          display contained "\d\+f"
"floating point number, with dot, optional exponent
syn match    cFloat          display contained "\d\+\.\d*\(e[-+]\=\d\+\)\=[fl]\="
"floating point number, starting with a dot, optional exponent
syn match    cFloat          display contained "\.\d\+\(e[-+]\=\d\+\)\=[fl]\=\>"
"floating point number, without dot, with exponent
syn match    cFloat          display contained "\d\+e[-+]\=\d\+[fl]\=\>"

" flag an octal number with wrong digits
syn match    cOctalError     display contained "0\o*[89]\d*"
syn case match

syn region   cCommentL       start="//" skip="\\$" end="$" keepend contains=@cCommentGroup,cSpaceError,@Spell
syn region   cComment        matchgroup=cCommentStart start="/\*" end="\*/" contains=@cCommentGroup,cCommentStartError,cSpaceError,@Spell extend

" keep a // comment separately, it terminates a preproc. conditional
syn match    cCommentError   display "\*/"
syn match    cCommentStartError display "/\*"me=e-1 contained

" Define the default highlighting.
" Only used when an item doesn't have highlighting yet
hi def link  pKeyword        Conditional
hi def link  pConstant       Constant
hi def link  pSyscall        Type
hi def link  pPythonCmds     Label
hi def link  pPython         PreProc
hi def link  pShellCmds      Label
hi def link  pShell          PreCondit
hi def link  pEllipsis       String
hi def link  pInputPkt       Todo
hi def link  pOutputPkt      Error

hi def link  cFormat         cSpecial
hi def link  cCppString      cString
hi def link  cCommentL       cComment
hi def link  cCommentStart   cComment
hi def link  cNumber         Number
hi def link  cOctal          Number
hi def link  cOctalZero      PreProc   " link this to Error if you want
hi def link  cFloat          Float
hi def link  cOctalError     cError
hi def link  cParenError     cError
hi def link  cErrInParen     cError
hi def link  cErrInBracket   cError
hi def link  cCommentError   cError
hi def link  cCommentStartError  cError
hi def link  cSpecialError   cError
hi def link  cError          Error
hi def link  cCommentString  cString
hi def link  cComment2String cString
hi def link  cCommentSkip    cComment
hi def link  cString         String
hi def link  cComment        Comment
hi def link  cSpecial        SpecialChar
hi def link  cCppOut         Comment

let b:current_syntax = "packetdrill"

let &cpo = s:cpo_save
unlet s:cpo_save
" vim: ts=8
