typedef union YYSTYPE {
  char* txt;
  u64   u64;
} YYSTYPE;

#define YYSTYPE_IS_DECLARED 1
#define YYSTYPE_IS_TRIVIAL 1
#define YY_NO_UNPUT 1

extern YYSTYPE yylval;

enum yytokentype {
	TK_STRING = 258,
	TK_U64,
	TK_U32,
	TK_NUM,
	TK_GC,
	TK_BM,
	TK_UUID,
	TK_VERSION,
	TK_LA_SIZE,
	TK_BM_BYTE_PER_BIT,
	TK_DEVICE_UUID,
	TK_TIMES,
	TK_FLAGS,
};

/* avoid compiler warnings about implicit declaration */
int yylex(void);
