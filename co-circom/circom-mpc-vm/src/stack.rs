type StackFrame<F> = Vec<F>;

#[derive(Clone)]
pub(crate) struct Stack<F: Clone> {
    stack: Vec<StackFrame<F>>,
}

impl<F: Clone> Default for Stack<F> {
    fn default() -> Self {
        Self {
            stack: vec![vec![]],
        }
    }
}

impl<F: Clone> Stack<F> {
    #[inline(always)]
    pub(crate) fn push_stack_frame(&mut self) {
        self.stack.push(StackFrame::default());
    }

    #[inline(always)]
    pub(crate) fn pop_stack_frame(&mut self) -> StackFrame<F> {
        self.stack.pop().expect("cannot pop empty stack")
    }

    #[inline(always)]
    pub(crate) fn peek_stack_frame(&mut self) -> &StackFrame<F> {
        self.stack.last().unwrap()
    }

    #[inline(always)]
    pub(crate) fn push(&mut self, val: F) {
        self.stack
            .last_mut()
            .expect("stack is empty and you want to push?")
            .push(val)
    }

    #[inline(always)]
    pub(crate) fn pop(&mut self) -> F {
        let stack_frame = self
            .stack
            .last_mut()
            .expect("stack is empty and you want to push?");
        stack_frame.pop().expect("stack frame is empty?")
    }

    #[inline(always)]
    pub(crate) fn frame_len(&self) -> usize {
        self.stack
            .last()
            .expect("stack is empty and you want to know length?")
            .len()
    }
}
