#lang scribble/text

@(require (for-syntax racket/base))

@(define test-list
   '(tests/racket/test
     tests/racket/contract/all))

@(define (indent-block n str)
   (define lines (string-split str "\n"))
   (define indent (make-string n #\space))
   (apply string-append
          (cons (first lines)
                (for/list ([line (in-list (rest lines))])
                  (string-append indent line "\n")))))

@(define-syntax (generate-test-steps stx)
   (syntax-case stx ()
     [(generate-test-steps tests)
      (with-syntax ([column (- (syntax-column stx) 1)])
      #`(indent-block column
                      (apply string-append
                             (for/list ([t (in-list tests)])
                               (format
                                #<<EOF
- name: Run ~a
  run: rack test -l ~a

EOF
                                t t)))))]))

name: Test CI

on: [push]

jobs:
  test:
    steps:
      @(generate-test-steps test-list)