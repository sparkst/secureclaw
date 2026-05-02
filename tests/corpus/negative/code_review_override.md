# Code Review Notes

This commit overrides the previous version of the helper function with
a simpler implementation. The previous version had a quadratic loop;
the new code uses a hash set. Tests cover both branches. Approved.
