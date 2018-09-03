// Copyright (c) 2018 Karl-Johan Alm
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Based on the martin-thoma.com blog post at
// https://martin-thoma.com/solving-linear-equations-with-gaussian-elimination/

#ifndef included_algo_gausselim_h_
#define included_algo_gausselim_h_

#include <cmath>
#include <vector>

namespace algo {

typedef double           val;
typedef std::vector<val> vec;
typedef std::vector<vec> mat;

/**
 * Take the A and b inputs for gaussian elimination solving for x in
 *      Ax=b
 * and convert the former into the format required by the gauss() function
 * below.
 */
inline void gausselim_prep(mat& A, const vec& b) {
    size_t n = A.size();
    for (size_t i = 0; i < b.size(); ++i) {
        A[n][i] = b[i];
    }
}

inline void gausselim_print(const mat& A) {
    int n = A.size();
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n + 1; ++j) {
            printf("%6.2lf\t", A[i][j]);
            if (j == n - 1) {
                printf("| ");
            }
        }
        printf("\n");
    }
}

/**
 * Perform gaussian elimination to solve the set of linear equations
 * in A, where the final row of A is the b vector in
 *      Ax=b
 * and the returned value is the x vector which lets A*x become b.
 */
inline vec gausselim(mat A) {
    size_t n = A.size();
    for (size_t i = 0; i < n; ++i) {
        // Search for maximum in this column
        val max_el = abs(A[i][i]);
        size_t max_row = i;
        for (size_t k = i + 1; k < n; ++k) {
            if (abs(A[k][i]) > max_el) {
                max_el = abs(A[k][i]);
                max_row = k;
            }
        }

        // Swap max row with current row (column by column)
        for (size_t k = i; k < n + 1; ++k) {
            val tmp = A[max_row][k];
            A[max_row][k] = A[i][k];
            A[i][k] = tmp;
        }

        // Make all rows below this one 0 in current column
        for (size_t k = i + 1; k < n; ++k) {
            val c = -A[k][i]/A[i][i];
            for (size_t j = i; j < n + 1; ++j) {
                if (i == j) {
                    A[k][j] = 0;
                } else {
                    A[k][j] += c * A[i][j];
                }
            }
        }
    }

    // Solve equation Ax=b for an upper triangular matrix A
    vec x(n);
    for (int i = n - 1; i >= 0; --i) {
        x[i] = A[i][n]/A[i][i];
        for (int k = i - 1; k >= 0; --k) {
            A[k][n] -= A[k][i] * x[i];
        }
    }
    return x;
}

} // namespace algo

#endif // included_algo_gausselim_h_
