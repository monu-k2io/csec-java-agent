package com.k2cybersecurity.instrumentator.custom;

import net.bytebuddy.build.HashCodeAndEqualsPlugin;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDefinition;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.description.type.TypeList;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

import java.util.*;

import static net.bytebuddy.matcher.ElementMatchers.hasSignature;

public class ByteBuddyElementMatchers {

    /**
     * Matches any type description that declares a super type that matches the provided matcher.
     * Exceptions during matching process are logged and ignored.
     *
     * @param matcher The type to be checked for being a super type of the matched type.
     * @param <T>     The type of the matched object.
     * @return A matcher that matches any type description that declares a super type that matches the
     * provided matcher.
     * @see ElementMatchers#hasSuperType(net.bytebuddy.matcher.ElementMatcher)
     */
    public static <T extends TypeDescription> ElementMatcher.Junction<T> safeHasSuperType(
            final ElementMatcher<? super TypeDescription> matcher) {
        return safeHasGenericSuperType(new SafeErasureMatcher(matcher));
    }

    /**
     * Matches any type description that declares a super type that matches the provided matcher.
     * Exceptions during matching process are logged and ignored.
     *
     * @param matcher The type to be checked for being a super type of the matched type.
     * @param <T>     The type of the matched object.
     * @return A matcher that matches any type description that declares a super type that matches the
     * provided matcher.
     * @see ElementMatchers#hasGenericSuperType(net.bytebuddy.matcher.ElementMatcher)
     */
    public static <T extends TypeDescription> ElementMatcher.Junction<T> safeHasGenericSuperType(
            final ElementMatcher<? super TypeDescription.Generic> matcher) {
        return new SafeHasSuperTypeMatcher<>(matcher);
    }

    /**
     * Wraps another matcher to assure that an element is not matched in case that the matching causes
     * an {@link Exception}. Logs exception if it happens.
     *
     * @param matcher The element matcher that potentially throws an exception.
     * @param <T>     The type of the matched object.
     * @return A matcher that returns {@code false} in case that the given matcher throws an
     * exception.
     */
    public static <T> ElementMatcher.Junction<T> failSafe(final ElementMatcher<? super T> matcher,
                                                          final String description) {
        return new SafeMatcher<>(matcher, false, description);
    }

    private static TypeDescription safeAsErasure(final TypeDefinition typeDefinition) {
        try {
            return typeDefinition.asErasure();
        } catch (final Exception e) {
            return null;
        }
    }

    /**
     * An element matcher that matches a super type. This is different from {@link
     * net.bytebuddy.matcher.HasSuperTypeMatcher} in the following way:
     *
     * <ul>
     * <li>Exceptions are logged
     * <li>When exception happens the rest of the inheritance subtree is discarded (since ByteBuddy
     * cannot load/parse type information for it) but search in other subtrees continues
     * </ul>
     *
     * <p>This is useful because this allows us to see when matcher's check is not complete (i.e. part
     * of it fails), at the same time it makes best effort instead of failing quickly (like {@code
     * failSafe(hasSuperType(...))} does) which means the code is more resilient to classpath
     * inconsistencies
     *
     * @param <T> The type of the matched entity.
     * @see net.bytebuddy.matcher.HasSuperTypeMatcher
     */
    @HashCodeAndEqualsPlugin.Enhance
    public static class SafeHasSuperTypeMatcher<T extends TypeDescription>
            extends ElementMatcher.Junction.AbstractBase<T> {

        /**
         * The matcher to apply to any super type of the matched type.
         */
        private final ElementMatcher<? super TypeDescription.Generic> matcher;

        /**
         * Creates a new matcher for a super type.
         *
         * @param matcher The matcher to apply to any super type of the matched type.
         */
        public SafeHasSuperTypeMatcher(final ElementMatcher<? super TypeDescription.Generic> matcher) {
            this.matcher = matcher;
        }

        @Override
        public boolean matches(final T target) {
            final Set<TypeDescription> checkedInterfaces = new HashSet<>();
            // We do not use foreach loop and iterator interface here because we need to catch exceptions
            // in {@code getSuperClass} calls
            TypeDefinition typeDefinition = target;
            while (typeDefinition != null) {
                if (matcher.matches(typeDefinition.asGenericType()) || hasInterface(typeDefinition,
                        checkedInterfaces)) {
                    return true;
                }
                typeDefinition = safeGetSuperClass(typeDefinition);
            }
            return false;
        }

        private TypeDefinition safeGetSuperClass(final TypeDefinition typeDefinition) {
            try {
                return typeDefinition.getSuperClass();
            } catch (final Exception e) {
                return null;
            }
        }

        /**
         * Matches a type's interfaces against the provided matcher.
         *
         * @param typeDefinition    The type for which to check all implemented interfaces.
         * @param checkedInterfaces The interfaces that have already been checked.
         * @return {@code true} if any interface matches the supplied matcher.
         */
        private boolean hasInterface(final TypeDefinition typeDefinition,
                                     final Set<TypeDescription> checkedInterfaces) {
            for (final TypeDefinition interfaceType : safeGetInterfaces(typeDefinition)) {
                final TypeDescription erasure = safeAsErasure(interfaceType);
                if (erasure != null) {
                    if (checkedInterfaces.add(interfaceType.asErasure()) && (
                            matcher.matches(interfaceType.asGenericType()) || hasInterface(interfaceType,
                                    checkedInterfaces))) {
                        return true;
                    }
                }
            }
            return false;
        }

        /**
         * TypeDefinition#getInterfaces() produces an interator which may throw an exception during
         * iteration if an interface is absent from the classpath.
         *
         * <p>This method exists to allow getting interfaces even if the lookup on one fails.
         */
        private List<TypeDefinition> safeGetInterfaces(final TypeDefinition typeDefinition) {
            final List<TypeDefinition> interfaceTypes = new ArrayList<>();
            try {
                final Iterator<TypeDescription.Generic> interfaceIter = typeDefinition.getInterfaces().iterator();
                while (interfaceIter.hasNext()) {
                    interfaceTypes.add(interfaceIter.next());
                }
            } catch (final Exception e) {
            }
            return interfaceTypes;
        }

        @Override
        public String toString() {
            return "safeHasSuperType(" + matcher + ")";
        }
    }

    /**
     * An element matcher that matches its argument's {@link TypeDescription.Generic} raw type against
     * the given matcher for a {@link TypeDescription}. As a wildcard does not define an erasure, a
     * runtime exception is thrown when this matcher is applied to a wildcard.
     *
     * <p>Catches and logs exception if it was thrown when getting erasure, returning false.
     *
     * @param <T> The type of the matched entity.
     * @see net.bytebuddy.matcher.ErasureMatcher
     */
    @HashCodeAndEqualsPlugin.Enhance
    public static class SafeErasureMatcher<T extends TypeDefinition>
            extends ElementMatcher.Junction.AbstractBase<T> {

        /**
         * The matcher to apply to the raw type of the matched element.
         */
        private final ElementMatcher<? super TypeDescription> matcher;

        /**
         * Creates a new erasure matcher.
         *
         * @param matcher The matcher to apply to the raw type.
         */
        public SafeErasureMatcher(final ElementMatcher<? super TypeDescription> matcher) {
            this.matcher = matcher;
        }

        @Override
        public boolean matches(final T target) {
            final TypeDescription erasure = safeAsErasure(target);
            if (erasure == null) {
                return false;
            } else {
                // We would like matcher exceptions to propagate
                return matcher.matches(erasure);
            }
        }

        @Override
        public String toString() {
            return "safeErasure(" + matcher + ")";
        }
    }

    /**
     * A fail-safe matcher catches exceptions that are thrown by a delegate matcher and returns an
     * alternative value.
     *
     * <p>Logs exception if it was thrown.
     *
     * @param <T> The type of the matched entity.
     * @see net.bytebuddy.matcher.FailSafeMatcher
     */
    @HashCodeAndEqualsPlugin.Enhance
    public static class SafeMatcher<T>
            extends ElementMatcher.Junction.AbstractBase<T> {

        /**
         * The delegate matcher that might throw an exception.
         */
        private final ElementMatcher<? super T> matcher;

        /**
         * The fallback value in case of an exception.
         */
        private final boolean fallback;

        /**
         * The text description to log if exception happens.
         */
        private final String description;

        /**
         * Creates a new fail-safe element matcher.
         *
         * @param matcher     The delegate matcher that might throw an exception.
         * @param fallback    The fallback value in case of an exception.
         * @param description Descriptive string to log along with exception.
         */
        public SafeMatcher(final ElementMatcher<? super T> matcher, final boolean fallback, final String description) {
            this.matcher = matcher;
            this.fallback = fallback;
            this.description = description;
        }

        @Override
        public boolean matches(final T target) {
            try {
                return matcher.matches(target);
            } catch (final Exception e) {
                return fallback;
            }
        }

        @Override
        public String toString() {
            return "safeMatcher(try(" + matcher + ") or " + fallback + ")";
        }
    }

    private static String safeTypeDefinitionName(final TypeDefinition td) {
        try {
            return td.getTypeName();
        } catch (final IllegalStateException ex) {
            final String message = ex.getMessage();
            if (message.startsWith("Cannot resolve type description for ")) {
                return message.replace("Cannot resolve type description for ", "");
            } else {
                return "?";
            }
        }
    }

    // TODO: add javadoc
    public static <T extends MethodDescription> ElementMatcher.Junction<T> hasSuperMethod(
            final ElementMatcher<? super MethodDescription> matcher) {
        return new HasSuperMethodMatcher<>(matcher);
    }

    // TODO: add javadoc
    @HashCodeAndEqualsPlugin.Enhance
    public static class HasSuperMethodMatcher<T extends MethodDescription>
            extends ElementMatcher.Junction.AbstractBase<T> {

        private final ElementMatcher<? super MethodDescription> matcher;

        public HasSuperMethodMatcher(final ElementMatcher<? super MethodDescription> matcher) {
            this.matcher = matcher;
        }

        @Override
        public boolean matches(final MethodDescription target) {
            if (target.isConstructor()) {
                return false;
            }
            final Junction<MethodDescription> signatureMatcher = hasSignature(target.asSignatureToken());
            TypeDefinition declaringType = target.getDeclaringType();
            final Set<TypeDefinition> checkedInterfaces = new HashSet<>();

            while (declaringType != null) {
                for (final MethodDescription methodDescription : declaringType.getDeclaredMethods()) {
                    if (signatureMatcher.matches(methodDescription) && matcher.matches(methodDescription)) {
                        return true;
                    }
                }
                if (matchesInterface(declaringType.getInterfaces(), signatureMatcher, checkedInterfaces)) {
                    return true;
                }
                declaringType = safeGetSuperClass(declaringType);
            }
            return false;
        }

        private boolean matchesInterface(final TypeList.Generic interfaces,
                                         final Junction<MethodDescription> signatureMatcher, final Set<TypeDefinition> checkedInterfaces) {
            for (final TypeDefinition type : interfaces) {
                if (!checkedInterfaces.contains(type)) {
                    checkedInterfaces.add(type);
                    for (final MethodDescription methodDescription : type.getDeclaredMethods()) {
                        if (signatureMatcher.matches(methodDescription) && matcher.matches(methodDescription)) {
                            return true;
                        }
                    }
                    if (matchesInterface(type.getInterfaces(), signatureMatcher, checkedInterfaces)) {
                        return true;
                    }
                }
            }
            return false;
        }

        private TypeDefinition safeGetSuperClass(final TypeDefinition typeDefinition) {
            try {
                return typeDefinition.getSuperClass();
            } catch (final Exception e) {
                return null;
            }
        }

        @Override
        public String toString() {
            return "hasSuperMethodMatcher(" + matcher + ")";
        }
    }
}
