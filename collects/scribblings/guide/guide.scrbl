#lang scribble/doc
@require[scribble/manual]
@require[scribble/eval]
@require["guide-utils.ss"]

@title[#:tag-prefix '(lib "scribblings/guide/guide.scrbl") 
       #:tag "top"]{A Guide to PLT Scheme}

This guide is intended for programmers who are new to Scheme, new to PLT
Scheme, or new to some part of PLT Scheme. It assumes
programming experience, so if you are new to programming, consider
instead reading @|HtDP|. If you want a quick and pretty overview of PLT
Scheme, start with @|Quick|.

@seclink["to-scheme"]{Chapter 2} provides a brief introduction to
Scheme. From @seclink["datatypes"]{Chapter 3} on, this guide dives
into details---covering much of the PLT Scheme toolbox, but leaving
precise details to @|MzScheme| and other reference manuals.

@table-of-contents[]

@include-section["welcome.scrbl"]

@include-section["to-scheme.scrbl"]

@include-section["data.scrbl"]

@include-section["forms.scrbl"]

@include-section["define-struct.scrbl"]

@include-section["modules.scrbl"]

@include-section["io.scrbl"]

@; ----------------------------------------------------------------------
@section[#:tag "contracts"]{Contracts}

In the reference manual, the documentation for each procedure
describes the acceptable arguments and the result of the procedure
using @idefterm{contracts}.

@; ----------------------------------------------------------------------
@include-section["class.scrbl"]


@; ----------------------------------------------------------------------
@section[#:tag "control"]{Exceptions and Control}


@; ----------------------------------------------------------------------
@include-section["for.scrbl"]


@; ----------------------------------------------------------------------
@section[#:tag "regexp"]{Regular-Expression Matching@aux-elem{ (Regexps)}}


@; ----------------------------------------------------------------------
@section[#:tag "match"]{Pattern Matching}

@subsection{Simple Dispatch: @scheme[case]}

The @scheme[case] form dispatches to a clause by matching the result
of an expression to the values for the clause:

@specform[(case [(_datum ...+) expr ...+]
                ...)]

@; ----------------------------------------------------------------------
@include-section["qq.scrbl"]

@; ----------------------------------------------------------------------
@section[#:tag "units"]{Units (Higher-Order Modules)}


@; ----------------------------------------------------------------------
@section[#:tag "threads"]{Threads}

@subsection[#:tag "parameters"]{Parameters}

A @deftech{parameter} holds a kind of global option. For example,
there is a parameter that determines the default destination for
printed output.

@; ----------------------------------------------------------------------
@include-section["macros.scrbl"]


@; ----------------------------------------------------------------------
@include-section["namespaces.scrbl"]


@; ----------------------------------------------------------------------
@section[#:tag "macros"]{Reader Extension}

@; ----------------------------------------------------------------------
@section[#:tag "security"]{Security}


@; ----------------------------------------------------------------------
@section[#:tag "memory-management"]{Memory Management}

@subsection[#:tag "weakboxes"]{Weak Boxes}

@subsection[#:tag "ephemerons"]{Ephemerons}

@; ----------------------------------------------------------------------
@section[#:tag "performance"]{Performance}

Every definition or expression is compiled to an internal bytecode
format. Standard optimizations are applied when compiling the
bytecode. For example, in an environment where @scheme[+] has its
usual binding, the expression @scheme[(let ([x 1][y (lambda () 4)]) (+
1 (y)))] is compiled the same as the constant @scheme[5] due to
constant propagation, constant folding, and inlining optimizations.


@; ----------------------------------------------------------------------
@section[#:tag "ffi"]{Foreign-Function Interface@aux-elem{ (FFI)}}


@; ----------------------------------------------------------------------
@section[#:tag "scripts"]{Scripts}


@; ----------------------------------------------------------------------
@section[#:tag "mred"]{Graphical User Interfaces@aux-elem{ (GUIs)}}

@deftech{MrEd} is both a library and an executable. As a library,
 @scheme[(lib "mred/mred.ss")] provides class, interface, and function
 bindings for writing GUI programs. An an executable, @exec{mred}
 substitutes for @exec{mzscheme} to run MrEd programs. (The
 @exec{mzscheme} executable cannot run MrEd programs, because
 @exec{mzscheme} does not include primitive GUI support, and because
 some operating systems distinguish GUI applications from command-line
 applications.)

@; ----------------------------------------------------------------------
@section[#:tag "tools"]{More Tools}

In the @seclink["intro"]{introduction}, we mentioned that PLT Scheme
includes more tools bsides DrScheme and MzScheme:

@itemize{

 @tool["MrEd"]{extends MzScheme with graphical user interface (GUI)
 and drawing primitives}

 @tool["Setup PLT"]{a command-line tool for installation tasks}

 @tool["planet"]{a command-line tool for managing packages that are
 normally downloaded automatically, on demand}

 @tool["mzc"]{a command-line tool for miscellaneous tasks, such as
 compiling Scheme source, compiling C-implemented extensions to the
 run-time system, generating executables, and building distribution
 packages}

}

@; ----------------------------------------------------------------------

@index-section[]
