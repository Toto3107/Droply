def sumu(nums , target):
    left = 0
    right  = len(nums) -1
    while left  < right:
        current_sum = nums[left]  + nums[right]
        if current_sum == target:
            return left , right
        elif current_sum < target:
            left += 1
        else :
            right -= 1
    return -1
nums = [2,7,11,22]
target = 18
print(sumu(nums,target))

def validparent(s:str):
    bracket_map = {")": "(", "]": "[", "}": "{"}
    stack=[]
    for char in s:
        if char in bracket_map:
            topelm =stack.pop() if stack else '#'
            if bracket_map[char] != topelm:
                return False
        else : 
            stack.append(char)
    return len(stack) == 0
s=""
print(validparent(s))
def maxsub(nums):
    global_max = nums[0]
    currmax = nums[0]
    for c in nums[1:]:
        currmax = max (c, currmax + c)
        global_max = max(global_max , currmax)
    return global_max
nums = [-2,1,-3,4,-1,2,1,-5,4]
print(maxsub(nums))
def climbStairs(n: int) -> int:
    if n <= 2:
        return n
        
   
    dp = [0] * (n + 1)
    dp[1] = 1
    dp[2] = 2
    
    for i in range(3, n + 1):
        dp[i] = dp[i - 1] + dp[i - 2]
        
    return dp[n]
def maxProfit(prices: list[int]) -> int:
    if not prices:
        return 0
    min_price = float('inf')
    max_price  = 0
    for price in prices:
        if price < min_price:
            min_price = price
        elif price - min_price > max_price:
            max_price = price - min_price
    return max_price
def majorelem(nums):
    candidate = None
    count = 0
    for num in nums:
        if count == 0:
            candidate = nums
        count += [1 if num == candidate else -1]
    return candidate
class ListNode:
    def __init__(self, val=0, next=None):
        self.val = val
        self.next = next
def reverseList(head: ListNode) -> ListNode:
    prev = None
    curr = head
    while curr:
        nxt = curr.next
        curr.next = prev
        prev = curr
        curr = nxt
    return prev
def missingNumber(nums: list[int]) -> int:
    xor_sum = len(nums)
    
    for i , num in enumerate(nums):
        xor_sum ^= i ^ num
    return xor_sum
class TreeNode:
    def __init__(self, val=0, left=None, right=None):
        self.val = val
        self.left = left
        self.right = right
def isSymmetric(root: TreeNode) -> bool:
    if not root:
        return True
    def isMirror(t1: TreeNode, t2: TreeNode) -> bool:
        if not t1 and not t2:
            return True
        if not t1 or not t2:
            return False
        return (t1.val == t2.val and 
                isMirror(t1.left, t2.right) and 
                isMirror(t1.right, t2.left))
    return isMirror(root.left, root.right)
def floodFill(image: list[list[int]], sr: int, sc: int, color: int) -> list[list[int]]:
    rows , cols  =len(image) , len(image[0])
    start_color= image[sr][sc]
    if start_color == color:
        return image
    def dfs(r: int, c: int):
        if r < 0 or r >= rows or c < 0 or c >= cols or image[r][c] != start_color:
            return
        image[r][c] = color
        dfs(r + 1, c)  
        dfs(r - 1, c) 
        dfs(r, c + 1)  
        dfs(r, c - 1)
    dfs(sr, sc)
    return image

        