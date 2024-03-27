/* Check if our test cases are test-compiled against a sane environment.
 * This checks that an expected test failure actually fails
 * by trying to includ some non-existant file.
 */
#include <this-file-does-not-exist.h>
#error "INTENTIONAL BUILD FAILURE"
