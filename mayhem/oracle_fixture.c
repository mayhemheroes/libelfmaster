/* Known fixture for the libelfmaster oracle: a small -no-pie EXEC ELF with stable, named symbols
 * (helper_symbol, main) and the usual sections (.text, .symtab). mayhem/test.sh asserts these. */
int helper_symbol(int x)
{
    return x + 1;
}

int main(void)
{
    return helper_symbol(41) - 42;
}
