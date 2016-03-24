/*
 * Copyright 2016 CloudBans (https://cloudbans.xyz)
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 */

package xyz.cloudbans.totp;

public class TotpValidator {

    private TotpValidator() {
        throw new UnsupportedOperationException("Utility class.");
    }

    public static boolean isValidForDigits(int digits) {
        return digits == 6 || digits == 8;
    }

    public static int checkDigits(int digits) {
        if (!isValidForDigits(digits))
            throw new IllegalArgumentException("digits must be 6 or 8.");
        return digits;
    }
}
