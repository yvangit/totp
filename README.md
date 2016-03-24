# CloudBans TOTP [![Build Status](https://travis-ci.org/CloudBans/totp.svg?branch=master)](https://travis-ci.org/CloudBans/totp)

A simple library for dealing with *Time-based One-time Passwords*
(*otp*).

## Installation

The TOTP library is continually deployed to our Maven repository.

If you're using Maven for dependency management, add the following
repository to your `pom.xml`:

```xml
<repository>
    <id>cloudbans-repository</id>
    <url>https://repo.cloudbans.xyz/content/groups/public/</url>
</repository>
```

Then you can specify the dependency:

```xml
<dependency>
    <groupId>xyz.cloudbans</groupId>
    <artifactId>totp</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

## Example usage

```java
import xyz.cloudbans.totp.Totp;
import xyz.cloudbans.totp.TotpUriBuilder;

import java.util.Scanner;

public class Test {

    // In the real world you should generate an individual secret for each user
    private static final byte[] SECRET = new byte[] { -5, -22, -68, -90, 45, 32, 102, -36, 108, 101 };

    public static void main(String[] args) {
        Totp totp = new Totp();

        TotpUriBuilder builder = TotpUriBuilder.builder("cloudbans_totp_demo:demo@cloudbans.xyz", SECRET);
        System.out.println("URL: " + builder.build());
        System.out.println("QR-Code: " + builder.buildQrCodeUrl());
        System.out.println();

        Scanner sc = new Scanner(System.in);
        String input, current;
        boolean match;
        do {
            System.out.print("Please enter the otp: ");
            input = sc.next();
            current = totp.generateNow(SECRET);
            match = input.equals(current);

            System.out.println("Expected: " + current);
            System.out.println("Given: " + input);
            System.out.println("Match? " + match);
        } while (!match);
        sc.close();
    }
}
```


## License

See [LICENSE.txt](/LICENSE.txt) for the Apache License, Version 2.0.
