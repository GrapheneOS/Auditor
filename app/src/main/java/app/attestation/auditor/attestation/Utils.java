package app.attestation.auditor.attestation;

import com.google.common.collect.ImmutableSet;

import org.bouncycastle.asn1.ASN1Boolean;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Iterator;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * Allow for backwards-compatible APIs usage of Google's attestation library in Android, without the need to use JDK 17 APIs.
 */
class Utils {

    // java.util.stream.Stream#ofNullable in JDK 17/API 34
    static <T> Stream<T> streamOfNullable(T t) {
        return t == null ? Stream.empty() : Stream.of(t);
    }

    // https://github.com/GrapheneOS/Auditor/blob/40ee574f71786a6a97498f925615797e9e86ac4a/app/src/main/java/app/attestation/auditor/attestation/Asn1Utils.java#L166
    static int intValueFromBigInteger(BigInteger bigInt, boolean strict) {
        if (bigInt.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0
                || bigInt.compareTo(strict ? BigInteger.ZERO : BigInteger.valueOf(Integer.MIN_VALUE)) < 0) {
            throw new IllegalArgumentException("INTEGER out of bounds");
        }
        return bigInt.intValue();
    }

    static boolean getBooleanFromAsn1Strict(ASN1Boolean booleanValue) {
        if (booleanValue.equals(ASN1Boolean.TRUE)) {
            return true;
        } else if (booleanValue.equals((ASN1Boolean.FALSE))) {
            return false;
        }
        throw new IllegalArgumentException("DER-encoded boolean values must contain either 0x00 or 0xFF");
    }

    static <T> ImmutableSet<T> collectToImmutableSet(Stream<T> stream) {
        return ImmutableSet.<T>builder().addAll(stream.collect(Collectors.toSet())).build();
    }

    // com.google.common.collect.stream.Stream#stream from guava-jre library
    public static <T extends Object> Stream<T> stream(Iterable<T> iterable) {
        return (iterable instanceof Collection<T>)
                ? ((Collection<T>) iterable).stream()
                : StreamSupport.stream(iterable.spliterator(), false);
    }

    private Utils() {}
}
